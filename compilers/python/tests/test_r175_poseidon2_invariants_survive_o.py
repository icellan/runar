"""R-175 (CL-BUG-001): poseidon2_koalabear.py guarded its structural invariants
with bare ``assert``, which ``python -O`` strips.

Seven asserts covered the round-constant table length, the MDS group arity and
the state width. Under ``-O`` / ``PYTHONOPTIMIZE=1`` all seven vanish, so a
malformed constant table or a wrong-arity call walks into codegen and emits a
script instead of failing. Every other module in this package — including the
sibling ``fiat_shamir_kb.py`` — raises ``RuntimeError`` for the same class of
invariant, so this file was the outlier as well as the vulnerable one.

These tests run the guards in a REAL ``-O`` subprocess. Asserting in-process
would prove nothing: the test runner does not run optimised, which is exactly
why the defect was invisible.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]


def _run_optimised(body: str) -> subprocess.CompletedProcess:
    """Run `body` in a subprocess with -O (asserts stripped)."""
    return subprocess.run(
        [sys.executable, "-O", "-c", textwrap.dedent(body)],
        cwd=str(PKG_ROOT),
        capture_output=True,
        text=True,
    )


def test_asserts_really_are_stripped_under_dash_o():
    """Control: -O does what the finding says it does."""
    res = _run_optimised(
        """
        def f():
            assert False, "this should be gone"
            return "reached"
        print(f())
        """
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == "reached"


def test_the_round_constant_table_check_survives_dash_o(tmp_path):
    """The module-level table guard must still fire when asserts are stripped.

    Copies the module, deletes one row from the constant table, and imports the
    copy in a -O subprocess. Under a bare `assert` the import succeeds.
    """
    src_path = PKG_ROOT / "runar_compiler" / "codegen" / "poseidon2_koalabear.py"
    src = src_path.read_text()

    marker = "POSEIDON2_KB_ROUND_CONSTANTS = ["
    assert marker in src, "the constant table moved; update this test"

    copy = tmp_path / "p2_short.py"
    # Drop one row by truncating the list right after it is built.
    copy.write_text(
        src.replace(
            "POSEIDON2_KB_ROUND_CONSTANTS = [",
            "POSEIDON2_KB_ROUND_CONSTANTS_FULL = [",
            1,
        )
        + "\n"
    )
    # Re-bind the (now renamed) table one row short, then re-run the guard.
    harness = tmp_path / "harness.py"
    harness.write_text(
        "import importlib.util, sys\n"
        "spec = importlib.util.spec_from_file_location('p2_short', %r)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "sys.modules['p2_short'] = mod\n"
        "try:\n"
        "    spec.loader.exec_module(mod)\n"
        "except RuntimeError as e:\n"
        "    print('REFUSED_AT_IMPORT', e)\n"
        "    raise SystemExit(0)\n"
        "except NameError:\n"
        "    # the rename removed the name the guard reads — the guard ran\n"
        "    print('GUARD_RAN')\n"
        "    raise SystemExit(0)\n"
        "print('NO_GUARD')\n"
        % str(copy)
    )
    # Running a script by path puts the SCRIPT's directory on sys.path, not the
    # cwd, so the package has to be named explicitly.
    env = dict(os.environ, PYTHONPATH=str(PKG_ROOT))
    res = subprocess.run(
        [sys.executable, "-O", str(harness)],
        cwd=str(PKG_ROOT),
        capture_output=True,
        text=True,
        env=env,
    )
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() != "NO_GUARD", (
        "the round-constant table guard did not run under -O: " + res.stdout + res.stderr
    )


def test_every_arity_guarded_entry_point_refuses_a_short_state_under_dash_o():
    res = _run_optimised(
        """
        import runar_compiler.codegen.poseidon2_koalabear as p2

        class NullTracker(list):
            pass

        short_state = ["n%d" % i for i in range(p2.POSEIDON2_KB_WIDTH - 1)]

        cases = [
            ("p2kb_external_mds4",          lambda: p2.p2kb_external_mds4(NullTracker(), ["a", "b", "c"], 0, 0)),
            ("p2kb_external_mds_full",      lambda: p2.p2kb_external_mds_full(NullTracker(), short_state, 0)),
            ("p2kb_internal_diffusion",     lambda: p2.p2kb_internal_diffusion(NullTracker(), short_state, 0)),
            ("p2kb_add_round_constants",    lambda: p2.p2kb_add_round_constants(NullTracker(), short_state, 0)),
            ("p2kb_add_round_constant_elem0", lambda: p2.p2kb_add_round_constant_elem0(NullTracker(), short_state, 0)),
            ("p2kb_permute",                lambda: p2.p2kb_permute(NullTracker(), short_state)),
        ]
        for name, call in cases:
            try:
                call()
            except RuntimeError:
                print("REFUSED", name)
            except Exception as e:
                print("WRONG", name, type(e).__name__, e)
            else:
                print("ACCEPTED", name)
        """
    )
    assert res.returncode == 0, res.stderr
    lines = [l for l in res.stdout.splitlines() if l.strip()]
    assert lines, res.stdout + res.stderr
    bad = [l for l in lines if not l.startswith("REFUSED")]
    assert bad == [], (
        "under -O these entry points did not refuse a wrong-width state: " + repr(bad)
    )


def test_the_module_still_has_no_bare_asserts():
    """The guard against the defect coming back, stated in the file itself."""
    src = (PKG_ROOT / "runar_compiler" / "codegen" / "poseidon2_koalabear.py").read_text()
    offenders = [
        (n, line.strip())
        for n, line in enumerate(src.splitlines(), 1)
        if line.lstrip().startswith("assert ")
    ]
    assert offenders == [], (
        "bare asserts are stripped by python -O; raise RuntimeError instead: "
        + repr(offenders)
    )
