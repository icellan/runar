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
audit's G-6 gap. Both skip cleanly otherwise — EXCEPT in CI, where either
missing dependency is treated as a hard failure (T-8 from
audits/cross-language-completeness-20260514.md §5.2; N-209).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _spec_missing(module_name: str) -> bool:
    """``importlib.util.find_spec`` for a dotted name imports its parent
    packages first and raises ``ModuleNotFoundError`` if one is absent
    (e.g. ``runar`` not on ``PYTHONPATH``), rather than returning ``None``
    the way it does for a missing top-level module. Treat either outcome
    as "missing"."""
    try:
        return importlib.util.find_spec(module_name) is None
    except ModuleNotFoundError:
        return True


# N-209: in CI we want a missing `bsv-sdk`, or a `runar-py` not on
# PYTHONPATH, to be loud, not a silent skip. The Python compiler CI job
# (``.github/workflows/ci.yml`` → ``python-compiler``) explicitly installs
# `bsv-sdk` and puts `packages/runar-py` on `PYTHONPATH` so this module runs
# its real path. If a future CI change drops either, the silent
# importorskips below would let this smoke test vanish from CI uncaught.
# Mirrors test_script_vm.py's T-8 guard for both of this file's optional
# dependencies.
if os.environ.get("CI") and _spec_missing("bsv"):
    pytest.fail(
        "test_cli_debug.py: CI environment detected ($CI is set) but the "
        "optional `bsv-sdk` package is not installed — this module's tests "
        "would silently skip. Install the `script-vm` extra in CI "
        "(`pip install runar[script-vm]` or `pip install bsv-sdk`). See "
        "audits/cross-language-completeness-20260514.md T-8.",
        pytrace=False,
    )
if os.environ.get("CI") and _spec_missing("runar.sdk.script_vm"):
    pytest.fail(
        "test_cli_debug.py: CI environment detected ($CI is set) but "
        "`runar.sdk.script_vm` is not importable — `packages/runar-py` is "
        "missing from PYTHONPATH and this module's tests would silently "
        "skip. Set PYTHONPATH to include `packages/runar-py` in CI (see "
        "`.github/workflows/ci.yml`'s `python-compiler` job). See "
        "audits/cross-language-completeness-20260514.md T-8.",
        pytrace=False,
    )

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
    """OP_0 (hex 00) — pushes empty bytes; falsy. Must exit non-zero (F-221).

    Proves the failing verdict is reported both on stdout and as the exit
    status, so CI / scripts can rely on it. Does not prove anything about the
    interpreter itself.
    """
    proc = _run(["debug", "--script", "00"])
    assert proc.returncode != 0, (
        f"debug on a falsy script must exit non-zero; got: {proc.returncode}\n"
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
