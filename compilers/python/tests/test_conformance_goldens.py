"""Byte-identical golden diff harness for the Python compiler.

For every directory under ``conformance/tests/``, this test:
  1. Locates the Python-format source file (``*.runar.py``)
  2. Invokes the Python compiler via its module entry point
  3. Canonicalizes the ANF IR JSON (sort keys, strip ``sourceLoc``, 2-space indent)
  4. Asserts byte-for-byte equality against ``expected-ir.json`` and ``expected-script.hex``

The canonicalization matches ``conformance/runner/runner.ts::canonicalizeJson``.

Failures are collected and the first 5 are reported with concrete diffs; the
test only asserts after every fixture has been processed so the surface area
of real conformance gaps is fully visible in one run.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import pytest


HERE = Path(__file__).resolve().parent
PYTHON_COMPILER_DIR = HERE.parent
CONFORMANCE_DIR = PYTHON_COMPILER_DIR.parent.parent / "conformance" / "tests"


def _find_python_source(test_dir: Path) -> Optional[Path]:
    """Resolve the Python-format source file for a conformance fixture.

    Mirrors the TS runner (`conformance/runner/runner.ts`):
      1. If ``source.json`` exists and has a ``.runar.py`` entry in ``sources``,
         resolve it relative to the fixture directory.
      2. Otherwise fall back to the first ``*.runar.py`` file in the fixture dir.
    """
    config_path = test_dir / "source.json"
    if config_path.exists():
        try:
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            rel = (cfg.get("sources") or {}).get(".runar.py")
            if isinstance(rel, str):
                resolved = (test_dir / rel).resolve()
                if resolved.exists():
                    return resolved
        except (json.JSONDecodeError, OSError):
            pass  # fall through to glob

    for entry in sorted(test_dir.iterdir()):
        if entry.is_file() and entry.name.endswith(".runar.py"):
            return entry
    return None


def _canonicalize_value(v):
    if isinstance(v, dict):
        out = {}
        for k in sorted(v.keys()):
            if k == "sourceLoc":
                continue
            out[k] = _canonicalize_value(v[k])
        return out
    if isinstance(v, list):
        return [_canonicalize_value(x) for x in v]
    return v


def _canonicalize_json(s: str) -> str:
    """Parse JSON, strip sourceLoc, sort keys, re-serialize with 2-space indent."""
    parsed = json.loads(s)
    return json.dumps(_canonicalize_value(parsed), indent=2, ensure_ascii=False)


def _run_compiler(source_path: Path, flags: list[str]) -> subprocess.CompletedProcess:
    """Invoke the Python compiler module in the compilers/python directory."""
    env = os.environ.copy()
    cmd = [sys.executable, "-m", "runar_compiler", "--source", str(source_path), *flags]
    return subprocess.run(
        cmd,
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def _discover_fixtures() -> list[Path]:
    return sorted(p for p in CONFORMANCE_DIR.iterdir() if p.is_dir())


def _short_diff(expected: str, actual: str, limit: int = 12) -> str:
    exp_lines = expected.splitlines()
    act_lines = actual.splitlines()
    out: list[str] = []
    shown = 0
    for i in range(max(len(exp_lines), len(act_lines))):
        e = exp_lines[i] if i < len(exp_lines) else "<EOF>"
        a = act_lines[i] if i < len(act_lines) else "<EOF>"
        if e != a:
            out.append(f"    line {i + 1}:")
            out.append(f"      - expected: {e}")
            out.append(f"      + actual:   {a}")
            shown += 1
            if shown >= limit:
                out.append("    ... (truncated)")
                break
    if not out:
        out.append("    (strings differ but no line diff; likely trailing whitespace)")
    return "\n".join(out)


def test_conformance_goldens_python(capsys):
    assert CONFORMANCE_DIR.is_dir(), f"missing conformance dir: {CONFORMANCE_DIR}"
    dirs = _discover_fixtures()

    passed: list[str] = []
    missing: list[str] = []
    failures: list[tuple[str, str, str, str]] = []  # (name, kind, expected, actual)

    for test_dir in dirs:
        name = test_dir.name
        source = _find_python_source(test_dir)
        if source is None:
            missing.append(name)
            continue

        # Step 1: IR
        ir_proc = _run_compiler(source, ["--emit-ir", "--disable-constant-folding"])
        if ir_proc.returncode != 0:
            failures.append((name, "compile-ir", "", (ir_proc.stderr or ir_proc.stdout).strip()))
            continue
        actual_ir_raw = ir_proc.stdout

        # Step 2: script hex
        hex_proc = _run_compiler(source, ["--hex", "--disable-constant-folding"])
        if hex_proc.returncode != 0:
            failures.append((name, "compile-hex", "", (hex_proc.stderr or hex_proc.stdout).strip()))
            continue
        actual_hex = "".join(hex_proc.stdout.split()).lower()

        # Step 3: canonicalize both sides of the IR diff
        try:
            actual_ir = _canonicalize_json(actual_ir_raw)
        except Exception as e:
            failures.append((name, "canonicalize-actual-ir", "", f"{e}\n-- raw --\n{actual_ir_raw[:500]}"))
            continue

        expected_ir_path = test_dir / "expected-ir.json"
        if expected_ir_path.exists():
            try:
                expected_ir = _canonicalize_json(expected_ir_path.read_text(encoding="utf-8"))
            except Exception as e:
                failures.append((name, "canonicalize-expected-ir", "", str(e)))
                continue
            if actual_ir != expected_ir:
                failures.append((name, "ir-mismatch", expected_ir, actual_ir))
                continue

        expected_hex_path = test_dir / "expected-script.hex"
        if expected_hex_path.exists():
            expected_hex = "".join(expected_hex_path.read_text(encoding="utf-8").split()).lower()
            if actual_hex != expected_hex:
                failures.append((name, "script-mismatch", expected_hex, actual_hex))
                continue

        passed.append(name)

    total = len(dirs)
    lines: list[str] = []
    lines.append(
        f"\n=== Python conformance-goldens summary: {len(passed)} pass / "
        f"{len(failures)} fail / {len(missing)} missing-source (of {total} fixtures) ==="
    )
    if missing:
        lines.append("Missing .runar.py source files:")
        for n in missing:
            lines.append(f"  - {n}")
    for (name, kind, expected, actual) in failures[:5]:
        lines.append(f"\n--- FAIL: {name} ({kind}) ---")
        if kind == "ir-mismatch":
            lines.append(f"  expected {len(expected)} chars, actual {len(actual)} chars:")
            lines.append(_short_diff(expected, actual))
        elif kind == "script-mismatch":
            min_len = min(len(expected), len(actual))
            first_diff = min_len
            for i in range(min_len):
                if expected[i] != actual[i]:
                    first_diff = i
                    break
            lo = max(0, first_diff - 20)
            exp_hi = min(first_diff + 20, len(expected))
            act_hi = min(first_diff + 20, len(actual))
            lines.append(
                f"  expected {len(expected)} hex chars, actual {len(actual)} hex chars"
            )
            lines.append(
                f"  first diff at hex offset {first_diff} (byte {first_diff // 2})"
            )
            lines.append(f"  expected: ...{expected[lo:exp_hi]}...")
            lines.append(f"  actual:   ...{actual[lo:act_hi]}...")
        else:
            # compile error or canonicalization error
            lines.append(f"  {actual}")
    if len(failures) > 5:
        lines.append(f"\n... and {len(failures) - 5} more failures:")
        for (name, _kind, _e, _a) in failures[5:]:
            lines.append(f"  - {name}")

    print("\n".join(lines))

    assert not failures, (
        f"{len(failures)} of {total} fixtures failed conformance-goldens; "
        f"see captured stdout for details"
    )
