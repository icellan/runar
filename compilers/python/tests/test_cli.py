"""CLI-mode tests for the Python compiler (GAP-m5).

Exercises the two CLI entry points that previously had no dedicated
per-tier test (the conformance runner exercised them only indirectly):

  * ``--parse-only --source <file>``  — universal frontend coverage mode
  * ``--ir <path>``                   — compile from ANF IR JSON to script

Both are driven as real subprocesses so a CLI flag rename or argparse
regression fails locally instead of only surfacing in the conformance
harness.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PYTHON_COMPILER_DIR.parent.parent
CONFORMANCE_DIR = REPO_ROOT / "conformance" / "tests"
P2PKH_SOURCE = REPO_ROOT / "examples" / "python" / "p2pkh" / "P2PKH.runar.py"
BASIC_P2PKH = CONFORMANCE_DIR / "basic-p2pkh"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", *args],
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env=os.environ.copy(),
    )


# ---------------------------------------------------------------------------
# --parse-only
# ---------------------------------------------------------------------------


def test_parse_only_accepts_valid_source() -> None:
    assert P2PKH_SOURCE.exists(), f"missing fixture: {P2PKH_SOURCE}"
    proc = _run(["--parse-only", "--source", str(P2PKH_SOURCE)])
    assert proc.returncode == 0, f"--parse-only failed: {proc.stderr}"
    assert proc.stdout.strip() == "parser ok"


def test_parse_only_requires_source() -> None:
    # --parse-only without --source must error (it has nothing to parse).
    proc = _run(["--parse-only", "--ir", "ignored.json"])
    assert proc.returncode != 0
    assert "--parse-only requires --source" in proc.stderr


def test_parse_only_rejects_missing_file() -> None:
    proc = _run(["--parse-only", "--source", "/nonexistent/Contract.runar.py"])
    assert proc.returncode != 0
    assert "parse error" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# --ir (compile from ANF IR JSON)
# ---------------------------------------------------------------------------


def test_ir_mode_compiles_to_byte_frozen_script() -> None:
    ir_path = BASIC_P2PKH / "expected-ir.json"
    golden_hex = (BASIC_P2PKH / "expected-script.hex").read_text(encoding="utf-8").strip()
    assert ir_path.exists(), f"missing fixture: {ir_path}"

    proc = _run(["--ir", str(ir_path), "--hex", "--disable-constant-folding"])
    assert proc.returncode == 0, f"--ir compile failed: {proc.stderr}"
    assert proc.stdout.strip() == golden_hex


def test_no_input_flag_errors() -> None:
    # Neither --ir nor --source: usage error, exit 1.
    proc = _run([])
    assert proc.returncode == 1
    assert "Usage:" in proc.stderr


# ---------------------------------------------------------------------------
# --emit-ir + --emit-source-map (F-255)
#
# The --emit-ir branch printed the IR JSON and `return`ed unconditionally,
# before the code further down that services --emit-source-map ever ran.
# `--source X --emit-ir --emit-source-map Y` exited 0 and Y was never
# created — the request was silently dropped, not refused. Go had the
# identical bug (F-183) and Java was always correct ("GAP-002:
# --emit-source-map ... runs INDEPENDENTLY of --emit-ir"); this ports Go's
# fix (fall through into the full compile so the source map gets populated
# and written, then stop before the hex/artifact output) to the Python tier.
# ---------------------------------------------------------------------------


def test_emit_ir_with_emit_source_map_writes_the_source_map_and_prints_only_ir(
    tmp_path: Path,
) -> None:
    assert P2PKH_SOURCE.exists(), f"missing fixture: {P2PKH_SOURCE}"
    sm_path = tmp_path / "source-map.json"
    assert not sm_path.exists(), "sanity: source map path must not pre-exist"

    proc = _run(
        [
            "--source",
            str(P2PKH_SOURCE),
            "--emit-ir",
            "--emit-source-map",
            str(sm_path),
        ]
    )
    assert proc.returncode == 0, (
        f"--emit-ir --emit-source-map must exit 0\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )

    # The finding itself: the file must actually be written.
    assert sm_path.exists(), (
        f"--emit-source-map file was never written (F-255 regression); stderr: {proc.stderr}"
    )
    import json as _json

    sm_json = _json.loads(sm_path.read_text(encoding="utf-8"))
    assert "mappings" in sm_json, f"source map JSON must carry a 'mappings' key, got: {sm_json}"

    # --emit-ir's contract: stdout carries only the IR, never the full
    # artifact (which would carry a "script" field).
    stdout_json = _json.loads(proc.stdout)
    assert "contractName" in stdout_json, (
        f"stdout must be ANF IR (expected a contractName field), got: {proc.stdout}"
    )
    assert "script" not in stdout_json, (
        f"stdout must carry ONLY the IR, not the compiled artifact; got: {proc.stdout}"
    )


# ---------------------------------------------------------------------------
# --emit-source-map on every output mode (N-186)
#
# Zig and the TS CLI dropped --emit-source-map under --hex and for an IR
# input, exiting 0 with nothing written. This CLI already writes the map on
# those paths; the tests pin that so it cannot regress into the same silent
# drop. For --ir the input has no source locations, so the map is the empty
# {"mappings": []} wrapper. Proves: the file exists with that shape and
# stdout stays the requested output. Does not prove: other tiers' CLIs.
# ---------------------------------------------------------------------------


def _assert_source_map_written(proc: subprocess.CompletedProcess, sm_path: Path) -> dict:
    import json as _json

    assert proc.returncode == 0, f"must exit 0\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    assert sm_path.exists(), f"--emit-source-map file was never written (N-186); stderr: {proc.stderr}"
    sm_json = _json.loads(sm_path.read_text(encoding="utf-8"))
    assert "mappings" in sm_json, f"source map must carry a 'mappings' key, got: {sm_json}"
    return sm_json


def test_hex_with_emit_source_map_writes_the_source_map(tmp_path: Path) -> None:
    sm_path = tmp_path / "source-map.json"
    proc = _run(["--source", str(P2PKH_SOURCE), "--hex", "--emit-source-map", str(sm_path)])
    sm_json = _assert_source_map_written(proc, sm_path)
    assert sm_json["mappings"], "a real source compile must carry mappings"
    assert proc.stdout.strip() and all(c in "0123456789abcdef" for c in proc.stdout.strip())


@pytest.mark.parametrize("extra", [[], ["--hex"], ["--asm"]])
def test_ir_input_with_emit_source_map_writes_the_empty_source_map(
    tmp_path: Path, extra: list[str]
) -> None:
    sm_path = tmp_path / "source-map.json"
    proc = _run(
        ["--ir", str(BASIC_P2PKH / "expected-ir.json"), *extra, "--emit-source-map", str(sm_path)]
    )
    sm_json = _assert_source_map_written(proc, sm_path)
    assert sm_json["mappings"] == []
