"""CLI smoke tests for the Python compiler's `debug` subcommand (G-6).

The subcommand wraps ``runar.sdk.script_vm.ScriptVM`` from
``packages/runar-py``, which in turn wraps the optional ``bsv-sdk``
``Spend`` interpreter. Both are external to the compiler proper, so these
tests:

  * skip cleanly when ``bsv-sdk`` is not installed (mirrors the
    ``packages/runar-py/tests/test_script_vm.py`` convention), AND
  * skip cleanly when ``runar-py`` itself cannot be imported (i.e. when
    the user did not install it / hasn't put it on ``PYTHONPATH``).

When both are available the tests assert that the subcommand parses its
arguments and runs a trivial script (``OP_1 → final: pass``) without
crashing — the per-tier "doesn't crash" smoke check required by the
audit's G-6 gap.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

# Skip the whole module unless both bsv-sdk and runar-py are importable.
# Without bsv-sdk the runar.sdk.script_vm wrapper raises ImportError on use;
# without runar-py the subcommand cannot import the wrapper at all.
pytest.importorskip("bsv", reason="bsv-sdk not installed (runar[script-vm] extra)")

PYTHON_COMPILER_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PYTHON_COMPILER_DIR.parent.parent
RUNAR_PY_DIR = REPO_ROOT / "packages" / "runar-py"

# Put packages/runar-py on PYTHONPATH so the subprocess can import runar.*.
# Mirrors how examples/python tests resolve their runar import.
pytest.importorskip("runar.sdk.script_vm", reason="runar-py not installed / on PYTHONPATH")


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    py_path = env.get("PYTHONPATH", "")
    extra = str(RUNAR_PY_DIR)
    env["PYTHONPATH"] = f"{extra}{os.pathsep}{py_path}" if py_path else extra
    return subprocess.run(
        [sys.executable, "-m", "runar_compiler", *args],
        cwd=str(PYTHON_COMPILER_DIR),
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def test_debug_trivial_script_passes() -> None:
    """OP_1 (hex 51) — pushes 1 onto the stack; final line must say 'pass'."""
    proc = _run(["debug", "--script", "51"])
    assert proc.returncode == 0, (
        f"debug on OP_1 must exit 0\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "step=1" in proc.stdout, f"expected at least one step line, got:\n{proc.stdout}"
    assert "final: pass" in proc.stdout, f"expected 'final: pass', got:\n{proc.stdout}"


def test_debug_missing_input_errors() -> None:
    """No --script and no --artifact: must exit non-zero with a diagnostic."""
    proc = _run(["debug"])
    assert proc.returncode != 0, "debug with no input must exit non-zero"
    assert "required" in proc.stderr.lower() or "usage" in proc.stderr.lower()


def test_debug_falsy_script_reports_fail() -> None:
    """OP_0 (hex 00) — pushes empty bytes; falsy. Wrapper must still exit 0."""
    proc = _run(["debug", "--script", "00"])
    # A falsy script is not a wrapper error.
    assert proc.returncode == 0, (
        f"wrapper must exit 0 for falsy scripts; got: {proc.returncode}\n"
        f"stderr: {proc.stderr}"
    )
    assert "final: fail" in proc.stdout, f"expected 'final: fail' for OP_0, got:\n{proc.stdout}"


def test_debug_artifact_loads_script_field(tmp_path) -> None:
    """--artifact <path>: load the 'script' field from a JSON artifact."""
    artifact = tmp_path / "trivial.json"
    artifact.write_text('{"script":"51"}', encoding="utf-8")
    proc = _run(["debug", "--artifact", str(artifact)])
    assert proc.returncode == 0, (
        f"debug --artifact must exit 0\nstdout: {proc.stdout}\nstderr: {proc.stderr}"
    )
    assert "final: pass" in proc.stdout, f"expected 'final: pass', got:\n{proc.stdout}"
