"""N-209: ``test_cli_debug.py`` and
``test_f092_poseidon2_merkle_root_binds_every_limb.py`` must fail loudly
(not silently skip) in CI when their optional dependencies are missing.

Ports ``packages/runar-py/tests/test_script_vm.py``'s T-8 ``$CI``-is-set
``pytest.fail`` guard (audits/cross-language-completeness-20260514.md S5.2)
to this compiler's other two test modules that gate on the same optional
dependencies (``bsv-sdk``, and ``packages/runar-py`` on ``PYTHONPATH`` for
``runar.sdk.script_vm``): both currently only ``pytest.importorskip`` on
those names, so a CI job that drops either the ``bsv-sdk`` install step or
the ``PYTHONPATH=`` setup (``.github/workflows/ci.yml`` -> ``python-compiler``)
makes these modules vanish from CI with a green "1 skipped" instead of a
failure.

Each target module is run as its own ``pytest`` subprocess (a fresh
interpreter, so module-level import state from this file's own collection
cannot leak into it) under two legs:

  * missing ``runar.sdk.script_vm`` — ``PYTHONPATH`` scrubbed of
    ``packages/runar-py``.
  * missing ``bsv`` — simulated honestly via ``sys.modules["bsv"] = None``
    in the child interpreter before it imports pytest, which is what both
    ``importlib.util.find_spec`` and ``pytest.importorskip`` treat exactly
    like the package not being installed.

What this proves: with ``CI=1`` set, either missing dependency makes each
target module's pytest subprocess print the T-8 diagnostic and report no
skip (``"1 skipped"`` does not appear) — a hard failure instead of the
silent skip a lone-module run reports pre-fix (``"1 skipped"``, exit code 5
for "no tests collected"; inside the full ``pytest tests/`` run that same
skip reports exit 0, which is the actual CI-green scenario this closes).

What this does not prove: behaviour with ``CI`` unset still skips cleanly
when a dependency is missing (that path is unchanged and is exercised by
every local/non-CI run of these two modules), nor anything about the
modules' actual test bodies when the dependencies ARE present — that is
covered by their own existing test functions. The PYTHONPATH-scrub leg also
assumes ``runar-py`` is not separately pip-installed into the interpreter
running these tests (CI installs it only via ``PYTHONPATH``, never
``pip install``, so this holds today, but a dev environment with
``pip install -e packages/runar-py`` would make that leg's scrub a no-op).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
COMPILER_DIR = TESTS_DIR.parent
REPO_ROOT = COMPILER_DIR.parent.parent
RUNAR_PY_DIR = REPO_ROOT / "packages" / "runar-py"

TARGETS = [
    "test_cli_debug.py",
    "test_f092_poseidon2_merkle_root_binds_every_limb.py",
]


def _env_with_runar_py_on_path() -> dict:
    env = os.environ.copy()
    env["CI"] = "1"
    py_path = env.get("PYTHONPATH", "")
    extra = str(RUNAR_PY_DIR)
    env["PYTHONPATH"] = f"{extra}{os.pathsep}{py_path}" if py_path else extra
    return env


def _env_without_runar_py_on_path() -> dict:
    env = os.environ.copy()
    env["CI"] = "1"
    py_path = env.get("PYTHONPATH", "")
    runar_py_resolved = RUNAR_PY_DIR.resolve()
    parts = [
        p
        for p in py_path.split(os.pathsep)
        if p and Path(p).resolve() != runar_py_resolved
    ]
    if parts:
        env["PYTHONPATH"] = os.pathsep.join(parts)
    else:
        env.pop("PYTHONPATH", None)
    return env


def test_missing_pythonpath_fails_loud_in_ci() -> None:
    """CI=1, runar.sdk.script_vm unimportable (no PYTHONPATH) -> hard failure."""
    for target in TARGETS:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(TESTS_DIR / target), "-v"],
            cwd=str(COMPILER_DIR),
            capture_output=True,
            text=True,
            timeout=60,
            env=_env_without_runar_py_on_path(),
        )
        assert proc.returncode != 0, (
            f"{target}: expected a hard failure with CI=1 and "
            f"runar.sdk.script_vm off PYTHONPATH, got exit 0.\n"
            f"stdout:\n{proc.stdout}"
        )
        assert "CI environment detected" in proc.stdout, (
            f"{target}: expected the T-8 diagnostic in pytest output.\n"
            f"stdout:\n{proc.stdout}"
        )
        assert "1 skipped" not in proc.stdout, (
            f"{target}: expected a hard failure, not the silent "
            f"\"1 skipped\" this reports pre-fix.\nstdout:\n{proc.stdout}"
        )


def test_missing_bsv_fails_loud_in_ci() -> None:
    """CI=1, bsv simulated absent -> hard failure, even with PYTHONPATH set."""
    for target in TARGETS:
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.modules['bsv'] = None; "
                "import pytest; sys.exit(pytest.main(sys.argv[1:]))",
                str(TESTS_DIR / target),
                "-v",
            ],
            cwd=str(COMPILER_DIR),
            capture_output=True,
            text=True,
            timeout=60,
            env=_env_with_runar_py_on_path(),
        )
        assert proc.returncode != 0, (
            f"{target}: expected a hard failure with CI=1 and bsv "
            f"simulated absent, got exit 0.\nstdout:\n{proc.stdout}"
        )
        assert "CI environment detected" in proc.stdout, (
            f"{target}: expected the T-8 diagnostic in pytest output.\n"
            f"stdout:\n{proc.stdout}"
        )
        assert "1 skipped" not in proc.stdout, (
            f"{target}: expected a hard failure, not the silent "
            f"\"1 skipped\" this reports pre-fix.\nstdout:\n{proc.stdout}"
        )
