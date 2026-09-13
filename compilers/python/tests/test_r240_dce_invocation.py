"""R-240 (CL-GAP-034): Python's "Pass 4.75" DCE wrapper was defined and never
invoked, and the DCE module called itself standalone.

`compiler._eliminate_dead_code` was documented as a discrete named pass that
"runs as a safety net for any post-EC residual dead bindings". None of the three
pipeline entry points called it, so it ran never and guarded nothing.

The real sweep lives in `anf_optimize.optimize_ec`, AFTER its
`if not any_changed: return program` gate — so a program with no EC calls is not
DCE'd at all. That gate is load-bearing: moving the sweep ahead of it makes this
tier fail to compile 11 of the 78 conformance fixtures, the same 11 the TS tier
fails under the same probe (R-194). That is N-140.

This test pins the shape so the wiring cannot quietly change: the gate stays in
front of the sweep, and no module claims to be standalone while it is not.
"""

import re
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "runar_compiler"


def test_the_early_exit_still_precedes_the_dce_sweep():
    src = (PKG / "frontend" / "anf_optimize.py").read_text()

    gate = src.index("if not any_changed:")
    sweep = src.index("_eliminate_dead_bindings(")

    assert gate < sweep, (
        "the dead-binding sweep now runs before the early exit. That makes DCE "
        "standalone, which is what R-194/N-140 measured as breaking 11 "
        "conformance fixtures in two tiers. Fix DCE first, then move this."
    )


def test_no_module_claims_a_standalone_dce_pass():
    offenders = []
    for path in PKG.rglob("*.py"):
        text = path.read_text()
        for n, line in enumerate(text.splitlines(), 1):
            if re.search(r"standalone DCE pass", line) and "NOT standalone" not in line:
                # The corrected docstring quotes the old claim; allow the quote.
                context = "\n".join(text.splitlines()[max(0, n - 3):n])
                if "used to say" not in context:
                    offenders.append(f"{path.name}:{n}: {line.strip()}")

    assert offenders == [], (
        "a module calls its DCE standalone; the only sweep in this tier runs "
        "behind optimize_ec's early exit: " + repr(offenders)
    )


def test_the_unreachable_pass_475_wrapper_is_gone():
    src = (PKG / "compiler.py").read_text()
    assert "def _eliminate_dead_code(" not in src, (
        "the Pass 4.75 wrapper is back; it has no callers and documents a safety "
        "net that does not run"
    )
    # And the whole-program entry it wrapped is still used where it really is.
    assert "eliminate_dead_code(probe)" in src, (
        "the @embedAlways probe no longer runs DCE on its deep copy"
    )
