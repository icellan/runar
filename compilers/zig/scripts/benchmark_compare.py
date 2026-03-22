#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ZIG_BIN = ROOT / "compilers" / "zig" / "zig-out" / "bin" / "runar-zig"
DEFAULT_RUST_BIN = ROOT / "compilers" / "rust" / "target" / "release" / "runar-compiler-rust"
DEFAULT_SOURCE_CONTRACTS = ROOT / "compilers" / "zig" / "benchmarks" / "contracts-source.txt"
DEFAULT_IR_CONTRACTS = ROOT / "compilers" / "zig" / "benchmarks" / "contracts-ir.txt"
TS_SOURCE_HELPER = ROOT / "compilers" / "zig" / "scripts" / "ts_compile_source_hex.mjs"
TS_IR_HELPER = ROOT / "compilers" / "zig" / "scripts" / "ts_compile_ir_hex.mjs"
TS_DIST = ROOT / "packages" / "runar-compiler" / "dist"
IMPLEMENTATION_ORDER = ("zig", "rust", "ts")
JS_MAX_SAFE_INTEGER = 9_007_199_254_740_991
IR_LOAD_CONST_INT_RE = re.compile(r'"kind"\s*:\s*"load_const"\s*,\s*"value"\s*:\s*(-?\d+)')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare Zig compiler performance against the TypeScript reference, with optional Rust runs."
    )
    parser.add_argument("mode", choices=["source", "ir"], help="Benchmark mode.")
    parser.add_argument("--contracts-file", type=Path, help="File containing one contract name per line.")
    parser.add_argument(
        "--contract",
        action="append",
        dest="contracts",
        default=[],
        help="Benchmark a specific contract. Repeatable. Overrides --contracts-file when provided.",
    )
    parser.add_argument("--iterations", type=int, default=10, help="Measured iterations per command.")
    parser.add_argument("--warmup", type=int, default=2, help="Warmup iterations per command.")
    parser.add_argument(
        "--node-bin",
        default="node",
        help="Node.js executable used for the TypeScript helper scripts.",
    )
    parser.add_argument(
        "--timeout-sec",
        type=float,
        default=120.0,
        help="Per-process timeout in seconds.",
    )
    parser.add_argument("--zig-bin", type=Path, default=DEFAULT_ZIG_BIN, help="Path to runar-zig binary.")
    parser.add_argument(
        "--with-rust",
        action="store_true",
        help="Also benchmark the Rust compiler on the same contracts and only aggregate parity-clean rows across all three compilers.",
    )
    parser.add_argument(
        "--rust-bin",
        type=Path,
        default=DEFAULT_RUST_BIN,
        help="Path to the Rust compiler binary used when --with-rust is enabled.",
    )
    parser.add_argument("--json-out", type=Path, help="Optional path for JSON results.")
    parser.add_argument("--label", help="Optional label embedded in JSON output for this run.")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print the suite summary without the per-contract table.",
    )
    parser.add_argument(
        "--show-commands",
        action="store_true",
        help="Print the resolved Zig and TypeScript benchmark commands for each contract.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue benchmarking other contracts after an error instead of stopping immediately.",
    )
    parser.add_argument(
        "--allow-failures",
        action="store_true",
        help="Exit 0 even if a contract errors or Zig/TS hex outputs do not match.",
    )
    parser.add_argument(
        "--list-contracts",
        action="store_true",
        help="Print the resolved contract list for the selected mode and exit.",
    )
    return parser.parse_args()


def read_contracts(path: Path) -> list[str]:
    names: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    if not names:
        raise SystemExit(f"no contracts found in {path}")
    return names


def normalize_repo_path(path: Path) -> Path:
    return path if path.is_absolute() else (ROOT / path).resolve()


def contracts_sha256(contracts: list[str]) -> str:
    digest = hashlib.sha256()
    for name in contracts:
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def normalize_hex(value: str) -> str:
    return "".join(value.split()).lower()


def shell_join(cmd: list[str]) -> str:
    return shlex.join(cmd)


def measurement_order_label(with_rust: bool) -> str:
    return "round-robin-rotating" if with_rust else "paired-alternating"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def path_sha256(path: Path) -> str:
    if path.is_file():
        return file_sha256(path)
    if not path.is_dir():
        raise FileNotFoundError(f"cannot hash missing path: {path}")

    digest = hashlib.sha256()
    for child in sorted(entry for entry in path.rglob("*") if entry.is_file()):
        rel = child.relative_to(path).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_sha256(child).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def extract_hex(raw: str) -> str:
    stripped = raw.strip()
    if not stripped:
        raise RuntimeError("command produced empty output")

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return normalize_hex(stripped)

    if isinstance(payload, dict):
        hex_value = payload.get("hex") or payload.get("scriptHex")
        if isinstance(hex_value, str) and hex_value.strip():
            return normalize_hex(hex_value)

    raise RuntimeError("command output was JSON but did not contain a hex/scriptHex field")


def resolve_source_path(contract: str) -> Path:
    direct = ROOT / "conformance" / "tests" / contract / f"{contract}.runar.ts"
    if direct.exists():
        return direct

    source_json = ROOT / "conformance" / "tests" / contract / "source.json"
    if source_json.exists():
        data = json.loads(source_json.read_text())
        source_map = data.get("sourceFiles") or data.get("sources") or {}
        rel = source_map.get(".runar.ts")
        if rel:
            return (source_json.parent / rel).resolve()

    raise FileNotFoundError(f"cannot resolve .runar.ts source for {contract}")


def resolve_ir_path(contract: str) -> Path:
    ir_path = ROOT / "conformance" / "tests" / contract / "expected-ir.json"
    if not ir_path.exists():
        raise FileNotFoundError(f"cannot resolve expected-ir.json for {contract}")
    return ir_path


def ensure_ir_json_safe_for_ts_helper(path: Path) -> None:
    text = path.read_text()
    for match in IR_LOAD_CONST_INT_RE.finditer(text):
        value = int(match.group(1))
        if abs(value) > JS_MAX_SAFE_INTEGER:
            raise RuntimeError(
                f"{path.relative_to(ROOT)} contains load_const integer {value} outside JS safe integer range; "
                "the TypeScript IR benchmark helper cannot benchmark this input safely"
            )


def run_checked(cmd: list[str], timeout_sec: float) -> str:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout_sec,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {shell_join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
    return proc.stdout.strip()


def time_one(cmd: list[str], timeout_sec: float) -> tuple[float, str]:
    start = time.perf_counter()
    output = run_checked(cmd, timeout_sec)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return elapsed_ms, output


def implementation_keys(commands: dict[str, list[str]]) -> list[str]:
    return [name for name in IMPLEMENTATION_ORDER if name in commands]


def rotate_implementations(commands: dict[str, list[str]], start_index: int) -> list[tuple[str, list[str]]]:
    names = implementation_keys(commands)
    rotated: list[tuple[str, list[str]]] = []
    for offset in range(len(names)):
        name = names[(start_index + offset) % len(names)]
        rotated.append((name, commands[name]))
    return rotated


def time_commands_round_robin(
    commands: dict[str, list[str]], warmup: int, iterations: int, timeout_sec: float
) -> tuple[dict[str, list[float]], dict[str, str]]:
    names = implementation_keys(commands)
    last_output = {name: "" for name in names}
    samples_ms = {name: [] for name in names}

    for index in range(warmup):
        for key, cmd in rotate_implementations(commands, index):
            _, output = time_one(cmd, timeout_sec)
            last_output[key] = output

    for index in range(iterations):
        for key, cmd in rotate_implementations(commands, index):
            elapsed_ms, output = time_one(cmd, timeout_sec)
            last_output[key] = output
            samples_ms[key].append(elapsed_ms)

    return samples_ms, last_output


def summarize(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    mean_ms = statistics.fmean(samples)
    stdev_ms = statistics.stdev(samples) if len(samples) > 1 else 0.0

    def percentile(fraction: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        index = (len(ordered) - 1) * fraction
        lower = math.floor(index)
        upper = math.ceil(index)
        if lower == upper:
            return ordered[lower]
        weight = index - lower
        return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

    return {
        "min_ms": min(samples),
        "mean_ms": mean_ms,
        "median_ms": statistics.median(samples),
        "p90_ms": percentile(0.90),
        "p95_ms": percentile(0.95),
        "max_ms": max(samples),
        "stdev_ms": stdev_ms,
        "cv_pct": (stdev_ms / mean_ms * 100.0) if mean_ms > 0 else 0.0,
    }


def summarize_overall(results: list[dict]) -> dict[str, float | int]:
    ok_rows = [row for row in results if row.get("status") == "ok"]
    matched_rows = [row for row in ok_rows if row.get("match")]

    def geometric_mean_for(key: str) -> float:
        speedups = [
            row[key]
            for row in matched_rows
            if isinstance(row.get(key), (int, float)) and row[key] > 0
        ]
        if not speedups:
            return 0.0
        return math.exp(statistics.fmean(math.log(value) for value in speedups))

    summary = {
        "contracts_total": len(results),
        "contracts_ok": len(ok_rows),
        "contracts_failed": len(results) - len(ok_rows),
        "matches": len(matched_rows),
        "mismatches": len(ok_rows) - len(matched_rows),
        "comparable_speedup_contracts": len(matched_rows),
        "geometric_mean_speedup_zig_vs_ts": geometric_mean_for("speedup_zig_vs_ts"),
    }
    if any(row.get("speedup_rust_vs_ts") is not None for row in ok_rows):
        summary["geometric_mean_speedup_rust_vs_ts"] = geometric_mean_for("speedup_rust_vs_ts")
    return summary


def diff_hex(zig_hex: str, ts_hex: str) -> dict[str, int | str | None]:
    limit = min(len(zig_hex), len(ts_hex))
    first_diff = next((index for index in range(limit) if zig_hex[index] != ts_hex[index]), None)
    if first_diff is None and len(zig_hex) == len(ts_hex):
        return {
            "first_diff_index": None,
            "zig_excerpt": None,
            "ts_excerpt": None,
            "length_delta": 0,
        }

    start = max((first_diff or limit) - 24, 0)
    end = min((first_diff or limit) + 24, max(len(zig_hex), len(ts_hex)))
    return {
        "first_diff_index": first_diff if first_diff is not None else limit,
        "zig_excerpt": zig_hex[start:end],
        "ts_excerpt": ts_hex[start:end],
        "length_delta": len(zig_hex) - len(ts_hex),
    }


def resolve_commands(
    mode: str, input_path: Path, zig_bin: Path, node_bin: str, rust_bin: Path | None
) -> dict[str, list[str]]:
    if mode == "source":
        commands = {
            "zig": [str(zig_bin), "--source", str(input_path), "--hex"],
            "ts": [node_bin, str(TS_SOURCE_HELPER), "--file", str(input_path)],
        }
        if rust_bin is not None:
            commands["rust"] = [str(rust_bin), "--source", str(input_path), "--hex"]
        return commands

    commands = {
        "zig": [str(zig_bin), "compile-ir", str(input_path), "--hex"],
        "ts": [node_bin, str(TS_IR_HELPER), "--file", str(input_path)],
    }
    if rust_bin is not None:
        commands["rust"] = [str(rust_bin), "--ir", str(input_path), "--hex"]
    return commands


def impl_payload(cmd: list[str], raw_hex: str, samples: list[float]) -> dict[str, object]:
    return {
        "command": cmd,
        "command_pretty": shell_join(cmd),
        "hex_len": len(raw_hex),
        "samples_ms": samples,
        **summarize(samples),
    }


def benchmark_contract(
    contract: str,
    mode: str,
    zig_bin: Path,
    node_bin: str,
    rust_bin: Path | None,
    warmup: int,
    iterations: int,
    timeout_sec: float,
) -> dict:
    if mode == "source":
        input_path = resolve_source_path(contract)
    else:
        input_path = resolve_ir_path(contract)
        ensure_ir_json_safe_for_ts_helper(input_path)
    commands = resolve_commands(mode, input_path, zig_bin, node_bin, rust_bin)
    samples_ms, raw_outputs = time_commands_round_robin(commands, warmup, iterations, timeout_sec)
    hex_outputs = {name: extract_hex(raw_output) for name, raw_output in raw_outputs.items()}

    zig_match_ts = hex_outputs["zig"] == hex_outputs["ts"]
    rust_match_ts = hex_outputs["rust"] == hex_outputs["ts"] if "rust" in hex_outputs else None
    zig_match_rust = hex_outputs["zig"] == hex_outputs["rust"] if "rust" in hex_outputs else None
    match = zig_match_ts and (rust_match_ts if rust_match_ts is not None else True)

    zig = impl_payload(commands["zig"], hex_outputs["zig"], samples_ms["zig"])
    ts = impl_payload(commands["ts"], hex_outputs["ts"], samples_ms["ts"])
    rust = impl_payload(commands["rust"], hex_outputs["rust"], samples_ms["rust"]) if "rust" in commands else None

    speedup_zig_vs_ts = ts["mean_ms"] / zig["mean_ms"] if match and zig["mean_ms"] > 0 else None
    speedup_rust_vs_ts = ts["mean_ms"] / rust["mean_ms"] if match and rust is not None and rust["mean_ms"] > 0 else None
    speedup_zig_vs_rust = rust["mean_ms"] / zig["mean_ms"] if match and rust is not None and zig["mean_ms"] > 0 else None
    input_bytes = input_path.stat().st_size

    hex_diff: dict[str, dict[str, int | str | None]] = {}
    if not zig_match_ts:
        hex_diff["zig_vs_ts"] = diff_hex(hex_outputs["zig"], hex_outputs["ts"])
    if rust is not None and not rust_match_ts:
        hex_diff["rust_vs_ts"] = diff_hex(hex_outputs["rust"], hex_outputs["ts"])
    if rust is not None and not zig_match_rust:
        hex_diff["zig_vs_rust"] = diff_hex(hex_outputs["zig"], hex_outputs["rust"])

    return {
        "status": "ok",
        "contract": contract,
        "input": str(input_path.relative_to(ROOT)),
        "input_bytes": input_bytes,
        "input_sha256": file_sha256(input_path),
        "mode": mode,
        "match": match,
        "comparable": match,
        "zig_match_ts": zig_match_ts,
        "rust_match_ts": rust_match_ts,
        "zig_match_rust": zig_match_rust,
        "zig": zig,
        "rust": rust,
        "ts": ts,
        "hex_diff": hex_diff or None,
        "speedup_zig_vs_ts": speedup_zig_vs_ts,
        "speedup_rust_vs_ts": speedup_rust_vs_ts,
        "speedup_zig_vs_rust": speedup_zig_vs_rust,
        "delta_mean_ms_zig_vs_ts": (ts["mean_ms"] - zig["mean_ms"]) if match else None,
        "delta_mean_ms_rust_vs_ts": (ts["mean_ms"] - rust["mean_ms"]) if match and rust is not None else None,
    }


def benchmark_contract_safe(
    contract: str,
    mode: str,
    zig_bin: Path,
    node_bin: str,
    rust_bin: Path | None,
    warmup: int,
    iterations: int,
    timeout_sec: float,
) -> dict:
    try:
        return benchmark_contract(contract, mode, zig_bin, node_bin, rust_bin, warmup, iterations, timeout_sec)
    except Exception as exc:
        return {
            "status": "error",
            "contract": contract,
            "mode": mode,
            "error": str(exc),
        }


def infer_suite_name(mode: str, contracts_file: Path | None, contracts: list[str]) -> str:
    if contracts_file is None:
        if len(contracts) == 1:
            return f"{mode}-single-{contracts[0]}"
        return f"{mode}-adhoc"
    return contracts_file.stem


def format_speedup(speedup: float) -> str:
    if speedup <= 0:
        return "n/a"
    if speedup >= 1.0:
        return f"{speedup:.2f}x faster"
    return f"{(1.0 / speedup):.2f}x slower"


def print_run_header(
    args: argparse.Namespace, contracts_file: Path | None, contracts: list[str], environment: dict[str, object]
) -> None:
    suite_name = infer_suite_name(args.mode, contracts_file, contracts)
    print(f"# Runar benchmark ({args.mode})")
    print()
    print(f"suite: {suite_name}")
    print(f"contracts: {len(contracts)}")
    print(f"iterations: {args.iterations}")
    print(f"warmup: {args.warmup}")
    print(f"timeout_sec: {args.timeout_sec:g}")
    print(f"measurement_order: {measurement_order_label(args.with_rust)}")
    print(f"zig_bin: {args.zig_bin}")
    if args.with_rust:
        print(f"rust_bin: {args.rust_bin}")
    print(f"node_bin: {args.node_bin}")
    if args.label:
        print(f"label: {args.label}")
    if contracts_file is not None:
        print(f"contracts_file: {contracts_file.relative_to(ROOT)}")
    if environment.get("git_commit"):
        dirty_suffix = " dirty" if environment.get("git_dirty") else ""
        print(f"git_commit: {environment['git_commit']}{dirty_suffix}")
    if environment.get("zig_version"):
        print(f"zig_version: {environment['zig_version']}")
    if environment.get("node_version"):
        print(f"node_version: {environment['node_version']}")
    print()


def print_report(
    args: argparse.Namespace, results: list[dict], contracts_file: Path | None, contracts: list[str], environment: dict[str, object]
) -> None:
    print_run_header(args, contracts_file, contracts, environment)
    if not args.summary_only:
        if args.with_rust:
            print("| contract | input bytes | zig mean ms | rust mean ms | ts mean ms | zig vs ts | rust vs ts | parity |")
            print("|---|---:|---:|---:|---:|---|---|---|")
        else:
            print("| contract | input bytes | zig mean ms | zig p95 ms | ts mean ms | ts p95 ms | zig vs ts | hex match | zig cv | ts cv |")
            print("|---|---:|---:|---:|---:|---:|---|---|---:|---:|")
        for row in results:
            if row.get("status") != "ok":
                if args.with_rust:
                    print(f"| {row['contract']} | error | error | error | error | error | error | no |")
                else:
                    print(f"| {row['contract']} | error | error | error | error | error | error | no | n/a | n/a |")
                continue
            if args.with_rust:
                print(
                    f"| {row['contract']} | "
                    f"{row['input_bytes']} | "
                    f"{row['zig']['mean_ms']:.2f} | "
                    f"{row['rust']['mean_ms']:.2f} | "
                    f"{row['ts']['mean_ms']:.2f} | "
                    f"{format_speedup(row['speedup_zig_vs_ts']) if row['match'] else 'n/a'} | "
                    f"{format_speedup(row['speedup_rust_vs_ts']) if row['match'] else 'n/a'} | "
                    f"{'yes' if row['match'] else 'no'} |"
                )
            else:
                print(
                    f"| {row['contract']} | "
                    f"{row['input_bytes']} | "
                    f"{row['zig']['mean_ms']:.2f} | "
                    f"{row['zig']['p95_ms']:.2f} | "
                    f"{row['ts']['mean_ms']:.2f} | "
                    f"{row['ts']['p95_ms']:.2f} | "
                    f"{format_speedup(row['speedup_zig_vs_ts']) if row['match'] else 'n/a'} | "
                    f"{'yes' if row['match'] else 'no'} | "
                    f"{row['zig']['cv_pct']:.1f}% | "
                    f"{row['ts']['cv_pct']:.1f}% |"
                )
    summary = summarize_overall(results)
    print()
    print(f"contracts: {summary['contracts_total']} total, {summary['contracts_ok']} ok, {summary['contracts_failed']} failed")
    print(f"hex parity: {summary['matches']} match, {summary['mismatches']} mismatch")
    if summary["comparable_speedup_contracts"] > 0:
        print(f"geomean speedup zig vs ts (parity-matched rows only, n={summary['comparable_speedup_contracts']}): {summary['geometric_mean_speedup_zig_vs_ts']:.2f}x")
        if args.with_rust:
            print(f"geomean speedup rust vs ts (parity-matched rows only, n={summary['comparable_speedup_contracts']}): {summary['geometric_mean_speedup_rust_vs_ts']:.2f}x")
    elif summary["contracts_ok"] > 0:
        print("geomean speedup: n/a (no parity-matched rows)")

    error_rows = [row for row in results if row.get("status") == "error"]
    if error_rows:
        print()
        print("errors:")
        for row in error_rows:
            print(f"- {row['contract']}: {row['error']}")

    mismatch_rows = [row for row in results if row.get("status") == "ok" and not row.get("match")]
    if mismatch_rows:
        print()
        print("hex mismatches:")
        for row in mismatch_rows:
            diffs = row.get("hex_diff") or {}
            for pair, diff in diffs.items():
                pair_left, pair_right = pair.split("_vs_")
                left = row[pair_left]
                right = row[pair_right]
                print(
                    f"- {row['contract']} ({pair_left} vs {pair_right}): "
                    f"{pair_left}_len={left['hex_len']} "
                    f"{pair_right}_len={right['hex_len']} "
                    f"first_diff={diff.get('first_diff_index')}"
                )
                if diff.get("zig_excerpt") or diff.get("ts_excerpt"):
                    print(f"  {pair_left}_excerpt={diff.get('zig_excerpt')}")
                    print(f"  {pair_right}_excerpt={diff.get('ts_excerpt')}")

    if args.show_commands:
        print()
        print("commands:")
        for row in results:
            if row.get("status") != "ok":
                continue
            print(f"- {row['contract']}")
            print(f"  zig: {row['zig']['command_pretty']}")
            if row.get("rust") is not None:
                print(f"  rust: {row['rust']['command_pretty']}")
            print(f"  ts:  {row['ts']['command_pretty']}")


def validate_args(args: argparse.Namespace) -> None:
    if args.iterations <= 0:
        raise SystemExit("--iterations must be >= 1")
    if args.warmup < 0:
        raise SystemExit("--warmup must be >= 0")
    if args.timeout_sec <= 0:
        raise SystemExit("--timeout-sec must be > 0")


def preflight(args: argparse.Namespace) -> None:
    missing_paths = [path for path in (TS_SOURCE_HELPER, TS_IR_HELPER) if not path.exists()]
    if missing_paths:
        joined = "\n".join(str(path) for path in missing_paths)
        raise SystemExit(f"missing benchmark helper script(s):\n{joined}")
    if not TS_DIST.exists():
        raise SystemExit(
            f"missing TypeScript dist output: {TS_DIST}\n"
            "build it first with:\n"
            "  cd /Users/satchmo/code/runar && pnpm --filter runar-compiler build"
        )
    if shutil.which(args.node_bin) is None:
        raise SystemExit(f"missing required executable: {args.node_bin}")
    if args.with_rust and not args.rust_bin.exists():
        raise SystemExit(
            f"missing Rust binary: {args.rust_bin}\n"
            "build it first with:\n"
            "  cd /Users/satchmo/code/runar/compilers/rust && cargo build --release"
        )


def maybe_read_command_output(cmd: list[str], timeout_sec: float = 10.0) -> str | None:
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_sec,
        )
    except Exception:
        return None

    if proc.returncode != 0:
        return None

    text = (proc.stdout or proc.stderr).strip()
    if not text:
        return None
    return text.splitlines()[0]


def collect_environment(args: argparse.Namespace) -> dict[str, object]:
    git_commit = maybe_read_command_output(["git", "rev-parse", "HEAD"])
    git_status = maybe_read_command_output(["git", "status", "--short", "--untracked-files=no"])
    node_version = maybe_read_command_output([args.node_bin, "--version"])
    zig_version = maybe_read_command_output(["zig", "version"])
    environment = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "cwd": str(ROOT),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "node_version": node_version,
        "zig_version": zig_version,
        "cpu_count": os.cpu_count(),
        "git_commit": git_commit,
        "git_dirty": bool(git_status),
    }
    if args.with_rust:
        environment["rustc_version"] = maybe_read_command_output(["rustc", "--version"])
    return environment


def build_payload(
    args: argparse.Namespace, contracts: list[str], contracts_file: Path | None, results: list[dict]
) -> dict:
    return {
        "schema_version": 5,
        "config": {
            "mode": args.mode,
            "suite": infer_suite_name(args.mode, contracts_file, contracts),
            "label": args.label,
            "contracts": contracts,
            "contracts_sha256": contracts_sha256(contracts),
            "contracts_file": str(contracts_file.relative_to(ROOT)) if contracts_file is not None else None,
            "contracts_file_sha256": file_sha256(contracts_file) if contracts_file is not None else None,
            "iterations": args.iterations,
            "warmup": args.warmup,
            "timeout_sec": args.timeout_sec,
            "measurement_order": measurement_order_label(args.with_rust),
            "zig_bin": str(args.zig_bin),
            "rust_bin": str(args.rust_bin) if args.with_rust else None,
            "node_bin": args.node_bin,
            "helpers": {
                "ts_source_helper": str(TS_SOURCE_HELPER.relative_to(ROOT)),
                "ts_ir_helper": str(TS_IR_HELPER.relative_to(ROOT)),
            },
            "artifacts": {
                "zig_bin_sha256": file_sha256(args.zig_bin),
                "rust_bin_sha256": file_sha256(args.rust_bin) if args.with_rust else None,
                "ts_source_helper_sha256": file_sha256(TS_SOURCE_HELPER),
                "ts_ir_helper_sha256": file_sha256(TS_IR_HELPER),
                "ts_dist_sha256": path_sha256(TS_DIST),
            },
            "recommended_invocation": shell_join(
                [
                    sys.executable,
                    str((ROOT / "compilers" / "zig" / "scripts" / "benchmark_compare.py").relative_to(ROOT)),
                    args.mode,
                    *(["--with-rust"] if args.with_rust else []),
                    "--iterations",
                    str(args.iterations),
                    "--warmup",
                    str(args.warmup),
                ]
            ),
        },
        "environment": collect_environment(args),
        "summary": summarize_overall(results),
        "results": results,
    }


def main() -> int:
    args = parse_args()
    validate_args(args)
    preflight(args)

    default_contracts_file = DEFAULT_SOURCE_CONTRACTS if args.mode == "source" else DEFAULT_IR_CONTRACTS
    contracts_file = None if args.contracts else normalize_repo_path(args.contracts_file or default_contracts_file)
    contracts = args.contracts or read_contracts(contracts_file)

    if args.list_contracts:
        for contract in contracts:
            print(contract)
        return 0

    if not args.zig_bin.exists():
        raise SystemExit(
            f"missing Zig binary: {args.zig_bin}\n"
            "build it first with:\n"
            "  cd /Users/satchmo/code/runar/compilers/zig && zig build -Doptimize=ReleaseFast"
        )

    results: list[dict] = []
    for name in contracts:
        row = benchmark_contract_safe(
            name,
            args.mode,
            args.zig_bin,
            args.node_bin,
            args.rust_bin if args.with_rust else None,
            args.warmup,
            args.iterations,
            args.timeout_sec,
        )
        results.append(row)
        if row.get("status") == "error" and not args.keep_going:
            break

    environment = collect_environment(args)
    print_report(args, results, contracts_file, contracts, environment)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        payload = build_payload(args, contracts, contracts_file, results)
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n")

    summary = summarize_overall(results)
    has_failures = summary["contracts_failed"] > 0 or summary["mismatches"] > 0
    if has_failures and not args.allow_failures:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
