"""Port of the TypeScript reference test
``packages/runar-compiler/src/__tests__/n051-branch-arm-private-helper.test.ts``.

N-051 — a private-helper call inside a BRANCH ARM must inline the callee.

``spec/semantics.md`` §6.3 defines a private method as source-level
substitution at every call site, and its canonical example is a helper call in
EXPRESSION position::

    private square(x: bigint): bigint { return x * x; }
    public verify(n: bigint): void { assert(this.square(n) < 100n); }
    // After inlining:
    public verify(n: bigint): void { assert(n * n < 100n); }

``spec/ir-format.md`` §4.7 keeps ``method_call`` in the canonical ANF
("Inlining happens in a later compiler phase"), so the substitution is stack
lowering's job — and stack lowering lowers an ``if``'s arms in a FRESH context.

The defect: ``codegen/stack.py``'s ``_lower_if`` built ``then_ctx`` /
``else_ctx`` with ``_LoweringContext(...)``, whose ``private_methods`` starts
EMPTY, and never copied ``self.private_methods`` into them. Inside an arm the
callee was therefore unknown, ``_lower_method_call`` fell through to
``_lower_call``, and the call lowered to a bare push. Python ACCEPTED and
emitted a script that never evaluates the helper — ``OP_0`` where the source
says ``OP_1ADD``::

    const v: bigint = p > 0n ? this.bump(p) : 0n;   // bump(x) = x + 1n

    ts / zig / ruby / java   7600a0638b6700776800a2         (correct)
    go                       7600a063006700776800a2         (silently wrong)
    python                   7600a063007c00776700776800a2   (silently wrong)
    rust                     rejected: "unknown function 'bump'"

That is the fund-safety half: the covenant deploys, and the arm computes a
value the contract never asked for.

The tier-independent proof, and the second test below: changing the callee body
from ``x + 1n`` to ``x + 2n`` changed NOTHING in Python's output. A compiler
that emits identical bytes for two different programs is not merely disagreeing
with its peers.

This is the branch-lowering arm contract (NEW-014 / NEW-018) again: an arm
context is constructed fresh, so every field it needs has to be re-plumbed by
hand. ``script_level_code_separator`` was re-plumbed by R-010 and
``renamed_params`` by issue #130 — both with a comment at the copy site.
``private_methods`` was missed. TS, Ruby and Java already copied it, which is
exactly why those tiers were correct.

The hexes are the SEVEN-TIER agreed output. Every tier pins the same strings,
which is what makes this a parity gate: a tier that lowers the fix differently
fails its own test.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

PRELUDE = """import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }
"""


def contract(body: str) -> str:
    return PRELUDE + body


# Helper called from a ternary arm.
TERNARY_ARM_PLUS_1 = contract("""  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
""")

# Same shape, different callee body — the body-independence probe.
TERNARY_ARM_PLUS_2 = contract("""  private bump(x: bigint): bigint { return x + 2n; }

  public m(p: bigint): void {
    const v: bigint = p > 0n ? this.bump(p) : 0n;
    assert(v >= this.s);
  }
}
""")

# Control: the same program with the helper inlined by hand.
TERNARY_ARM_MANUAL_INLINE = contract("""  public m(p: bigint): void {
    const v: bigint = p > 0n ? p + 1n : 0n;
    assert(v >= this.s);
  }
}
""")

# Helper called from an `if` STATEMENT arm.
IF_STATEMENT_ARM = contract("""  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = this.bump(p);
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
""")

# Control: the same `if` with no helper call in either arm.
IF_STATEMENT_ARM_NO_HELPER = contract("""  public m(p: bigint): void {
    let v: bigint = 0n;
    if (p > 0n) {
      v = p + 1n;
    } else {
      v = 0n;
    }
    assert(v >= this.s);
  }
}
""")

# Control: a helper call in ordinary statement position, outside any arm.
STATEMENT_POSITION = contract("""  private bump(x: bigint): bigint { return x + 1n; }

  public m(p: bigint): void {
    const v: bigint = this.bump(p);
    assert(v >= this.s);
  }
}
""")


def compile_script_hex(source: str, disable_constant_folding: bool) -> str:
    result = compile_from_source_str_with_result(
        source, "C.runar.ts", disable_constant_folding=disable_constant_folding
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize(
    "label,source,want",
    [
        ("ternary-arm/+1", TERNARY_ARM_PLUS_1, "7600a0638b6700776800a2"),
        ("ternary-arm/+2", TERNARY_ARM_PLUS_2, "7600a06352936700776800a2"),
        ("ternary-arm-manual-inline", TERNARY_ARM_MANUAL_INLINE, "7600a0638b6700776800a2"),
        (
            "if-statement-arm",
            IF_STATEMENT_ARM,
            "007800a0637c8b767676537a757777670076537a757768517a7500a2",
        ),
        (
            "if-statement-arm-no-helper",
            IF_STATEMENT_ARM_NO_HELPER,
            "007800a0637c8b7677670076537a757768517a7500a2",
        ),
        ("statement-position", STATEMENT_POSITION, "8b00a2"),
    ],
)
def test_seven_tier_script_for_branch_arm_private_helper(label, source, want, disable):
    got = compile_script_hex(source, disable)
    assert got == want, (
        f"{label} (disable_constant_folding={disable}): "
        "script hex diverged from the seven-tier agreed output"
    )


@pytest.mark.parametrize("disable", [True, False])
def test_ternary_arm_matches_manual_inline(disable):
    """spec/semantics.md §6.3: inlining IS substitution, so a helper call in a
    ternary arm and the hand-substituted program are the same program."""
    assert compile_script_hex(TERNARY_ARM_PLUS_1, disable) == compile_script_hex(
        TERNARY_ARM_MANUAL_INLINE, disable
    )


@pytest.mark.parametrize("disable", [True, False])
def test_callee_body_reaches_the_arm(disable):
    """The tier-independent oracle. No reference tier is consulted: a compiler
    that emits the same bytes for ``x + 1n`` and ``x + 2n`` has dropped the
    callee body, whatever its peers do."""
    assert compile_script_hex(TERNARY_ARM_PLUS_1, disable) != compile_script_hex(
        TERNARY_ARM_PLUS_2, disable
    )
