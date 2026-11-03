"""F-015 — a method parameter that shadows a MUTABLE property must stay the
parameter inside an ``if`` / ternary arm.

Issue #130 (stack layer): ``deserialize_state`` pushes each mutable property
under its own name, so a same-named method parameter would lose every name
lookup to the (shallower) property slot. ``_LoweringContext.__init__`` renames
the parameter's slot to ``__param_<name>`` and records the mapping in
``renamed_params``; ``_lower_load_param`` resolves through that map.

The defect: ``_lower_if`` lowers each arm in a FRESH ``_LoweringContext``. The
arm's stack is a clone of the parent's (so it carries the ``__param_<name>``
slot) but its ``renamed_params`` started EMPTY. A ``load_param`` inside the arm
therefore looked up the bare name and found the deserialized PROPERTY slot —
the pre-call on-chain state — instead of the caller's witness argument. The
compile succeeds; the arm silently reads the wrong value::

    public set(count: bigint, flag: boolean) {
      if (flag) { assert(count == 5n); }     // arm read this.count (stale)
      this.count = count;
    }

With on-chain state ``count = 5`` a caller passing ``set(7n, true)`` satisfied
a guard the source says must fail (``7 == 5``) — a FAIL-OPEN guard. The
real-engine proof of that spend is
``packages/runar-testing/src/__tests__/f015-python-param-shadow-branch-arm-vm.test.ts``.

Oracle (needs no reference tier): a parameter's NAME is not part of the
program. Alpha-renaming the parameter to a non-colliding name (``count`` ->
``newCount``) must compile to byte-identical script. Before the fix the
shadowing program's arm emitted ``OP_DUP`` (copy of the state value on top)
where the renamed program emits ``OP_n OP_PICK`` (the parameter slot).

What this proves: Python's stack lowering resolves a shadowing parameter to the
same slot inside an if-then arm, an if-else arm and a ternary arm as it does
for a non-colliding name, in both fold modes. What it does NOT prove: anything
about the other six tiers, or that the renamed program itself is correct —
that half is the real-engine test named above.
"""

from __future__ import annotations

import re

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

PRELUDE = """import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

"""

# Each body is written with the shadowing parameter name ``count``; the control
# is produced by alpha-renaming that parameter to ``newCount``.
THEN_ARM = """  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(count == 5n);
    }
    this.count = count;
  }
}
"""

ELSE_ARM = """  public set(count: bigint, flag: boolean) {
    if (flag) {
      assert(flag);
    } else {
      assert(count > 10n);
    }
    this.count = count;
  }
}
"""

TERNARY_ARM = """  public set(count: bigint, flag: boolean) {
    const v: bigint = flag ? count + 1n : 0n;
    assert(v != 3n);
    this.count = count;
  }
}
"""

# Control: the parameter is read only OUTSIDE any arm. This shape was already
# correct before the fix; it pins that the oracle is not vacuous.
NO_ARM = """  public set(count: bigint, flag: boolean) {
    assert(count != 3n);
    assert(flag);
    this.count = count;
  }
}
"""


def alpha_rename(body: str) -> str:
    return (
        body.replace("set(count: bigint", "set(newCount: bigint")
        .replace("this.count = count;", "this.count = newCount;")
        .replace("(count ", "(newCount ")
        .replace("? count ", "? newCount ")
    )


def compile_hex(body: str, disable_constant_folding: bool) -> str:
    result = compile_from_source_str_with_result(
        PRELUDE + body,
        "Probe.runar.ts",
        disable_constant_folding=disable_constant_folding,
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize(
    "label,body",
    [
        ("then-arm", THEN_ARM),
        ("else-arm", ELSE_ARM),
        ("ternary-arm", TERNARY_ARM),
        ("control/no-arm", NO_ARM),
    ],
)
def test_shadowing_param_is_alpha_equivalent_in_branch_arm(label, body, disable):
    renamed = alpha_rename(body)
    # The rename must actually have removed every read of the shadowing name.
    assert re.search(r"(?<![.\w])count\b", renamed) is None, renamed
    assert compile_hex(body, disable) == compile_hex(renamed, disable), (
        f"{label}: a parameter that shadows mutable property 'count' compiled "
        f"differently from the same program with the parameter renamed — the "
        f"arm read the deserialized state slot, not the witness argument"
    )
