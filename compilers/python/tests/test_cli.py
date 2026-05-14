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
