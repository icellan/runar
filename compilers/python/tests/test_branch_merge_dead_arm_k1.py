"""Three branch-merge defects fixed 2026-08-06, pinned to the seven-tier script.

Mirrors packages/runar-compiler/src/__tests__/branch-merge-k1-and-dead-arm.test.ts.

All three reproduced in ALL SEVEN TIERS, and all are the PALMER-1 family ("one
stack carrier asked to hold N live values") at the k=1 / k=2 arities the
2026-08-05 branch-merged-locals fix did not cover:

1.  FUND SAFETY, silent, fold-ON only.  An ``if`` whose condition folds to a
    compile-time constant, whose STATICALLY DEAD arm rebinds exactly TWO locals
    both read after the branch, resolved every post-branch operand to the WRONG
    stack slot.  Wrong in both directions: with ``s = -60267`` the source
    REJECTS and the deployed script ACCEPTED (a covenant guard bypassed); with
    ``s = 1000`` the source ACCEPTS and the deployed script REJECTED (an
    unspendable UTXO).  Every tier emitted the same wrong script, so cross-tier
    agreement held perfectly while all seven were wrong together.
2.  A single local rebound FROM ITSELF in BOTH arms (``m0 = m0 + 1n`` /
    ``m0 = m0 - 1n``) was REJECTED with "value not found on stack", in both fold
    modes, though the same shape compiles at k=2 and without an ``else``.
3.  The same k=1 merge under ANY compile-time-constant condition, fold-ON.

Fixes: ``frontend/constant_fold.py`` no longer blanks a statically-dead arm
(that erased the ``__merge$<i>`` result block both arms carry, so ONE stack slot
was registered for K physical results), and ``codegen/stack.py``'s
``_the multi-result branch node`` adopts the slot both arms rebound in place at
k=1.

The hexes are the SEVEN-TIER agreed output.  Every tier pins the same strings,
which is what makes this a parity gate: a tier that lowers the fix differently
fails its own test.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result


# ---------------------------------------------------------------------------
# Sources (TypeScript surface). Kept byte-identical across all seven tiers.
# ---------------------------------------------------------------------------

# k=2 locals rebound by a STATICALLY DEAD arm, both read after the branch.
DEAD_ARM_K2 = """import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  public m(p: bigint): void {
    let a: bigint = this.s;
    let b: bigint = -78n;
    if (false) {
      a = 1n;
      b = p;
    }
    assert(b <= a);
  }
}"""

# One local rebound FROM ITSELF in both arms, read after the branch.
SELF_READ_BOTH_ARMS = """import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (p > 0n) {
      m0 = (m0 + 1n);
    } else {
      m0 = (m0 - 1n);
    }
    assert(m0 > -1000000n);
  }
}"""

# The same k=1 merge under a compile-time-constant condition.
CONST_CONDITION_K1 = """import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (true) {
      m0 = 2n;
    } else {
      m0 = 3n;
    }
    assert(m0 > -1000000n);
  }
}"""


def compile_script_hex(source: str, disable_constant_folding: bool) -> str:
    result = compile_from_source_str_with_result(
        source, "C.runar.ts", disable_constant_folding=disable_constant_folding
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex


@pytest.mark.parametrize(
    "label,source,disable,want",
    [
        (
            "dead-arm-k2/fold-on", DEAD_ARM_K2, False,
            "00014e01ce006351547a6e7b757b7567527978557a7568527a75537a75527a7c7ba177",
        ),
        (
            "dead-arm-k2/fold-off", DEAD_ARM_K2, True,
            "00014e8f006351537a6e7b757b75676e547a7568527a75527a757ca1",
        ),
        (
            "self-read-both-arms/fold-on", SELF_READ_BOTH_ARMS, False,
            "000340420f0340428f7b7ca069517b00a06351787c9376776751787c94767768517a750340420f0340428f7b7ca07777",
        ),
        (
            "self-read-both-arms/fold-off", SELF_READ_BOTH_ARMS, True,
            "000340420f8fa069517c00a06351787c9376776751787c94767768517a750340420f8fa0",
        ),
        (
            "const-condition-k1/fold-on", CONST_CONDITION_K1, False,
            "000340420f0340428f7b7ca0695151635276776753767768517a750340420f0340428f7b7ca0777777",
        ),
        (
            "const-condition-k1/fold-off", CONST_CONDITION_K1, True,
            "000340420f8fa0695151635276776753767768517a750340420f8fa077",
        ),
    ],
)
def test_seven_tier_script(label, source, disable, want):
    got = compile_script_hex(source, disable)
    assert got == want, f"{label}: script hex diverged from the seven-tier agreed output"


def test_const_and_runtime_conditions_agree():
    """A constant condition must not be treated differently from a runtime one.

    Before the fix, only the k=2 dead-arm form broke, and only under folding --
    which is why the fold-OFF parity fuzzers were blind to it.
    """
    for cond in ("if (false) {", "if (true) {", "if (p > 0n) {"):
        for disable in (False, True):
            source = DEAD_ARM_K2.replace("if (false) {", cond, 1)
            compile_script_hex(source, disable)


def test_k2_sibling_and_no_else_sibling_still_compile():
    """The k=1 self-read shape used to be rejected while its neighbours compiled.

    A compiler that refuses a shape at one arity and accepts it at the next is
    reporting a hole in its own merge machinery, not a language restriction --
    which is why this was fixed rather than turned into a diagnostic.
    """
    k2 = (
        SELF_READ_BOTH_ARMS
        .replace("    let m0: bigint = 1n;", "    let m0: bigint = 1n;\n    let m1: bigint = 2n;", 1)
        .replace("      m0 = (m0 + 1n);", "      m0 = (m0 + 1n);\n      m1 = (m1 + 1n);", 1)
        .replace("      m0 = (m0 - 1n);", "      m0 = (m0 - 1n);\n      m1 = (m1 - 1n);", 1)
        .replace(
            "    assert(m0 > -1000000n);\n  }",
            "    assert((m0 > -1000000n) && (m1 > -1000000n));\n  }",
            1,
        )
    )
    no_else = SELF_READ_BOTH_ARMS.replace(
        "    } else {\n      m0 = (m0 - 1n);\n    }", "    }", 1
    )
    for source in (k2, no_else):
        for disable in (False, True):
            compile_script_hex(source, disable)
