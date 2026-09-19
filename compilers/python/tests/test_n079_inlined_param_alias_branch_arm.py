"""Port of the TypeScript reference test
``packages/runar-compiler/src/__tests__/n079-inlined-param-alias-branch-arm.test.ts``.

N-079 — the inlined argument alias must survive into a branch arm.

``spec/semantics.md`` §6.3 defines a private method as source-level
substitution at every call site. So this::

    private pay(v: bigint): void { ...uses v... }
    public  go(v: bigint) { this.pay(v * 2n); }

and the hand-substituted program (``const a = v * 2n;`` then the body with
``a`` in place of ``v``) are the SAME program and must compile to the same
script. That is an oracle needing no reference tier.

The defect: ``_inline_private_method_call`` pushes the caller's argument refs
onto the CURRENT lowering context (``push_param_alias``) and then lowers the
private method's body into it. When that body contains an ``if`` / ``for`` /
ternary, the arm is built by ``sub_context()`` — a FRESH context that did not
copy ``_param_alias_stack``. A read of the private's parameter inside the arm
therefore found no alias and fell through to ``load_param``, which resolved to
the CALLER's same-named parameter instead of the argument that was passed in.

The covenant's output amount became ``v + 100`` where the source says
``(v * 2) + 100`` — a continuation-hash mismatch (UTXO unspendable) or a wrong
payment. Nobody refused; five of the seven tiers silently emitted a different
program. Measured on the pre-fix HEAD, ``--disable-constant-folding``::

                   go   rust  python  zig  ruby  java  ts
    hand-inlined   705   705    705   705   705   705  705
    via helper     705   705    703   703   703   703  703

Go and Rust were right: Go's ``subContext`` already deep-copied the alias
stack, with a comment naming this exact hazard.

Fifth field of the same sub-context missed one at a time —
``scriptLevelCodeSeparator`` (R-010), ``renamedParams`` (#130),
``privateMethods`` (N-051), the three ``MethodScope`` fields (R-072), now the
alias stack. Same family as the NEW-014 / NEW-018 branch-lowering arm contract.

The (byte length, sha256-of-hex) pairs below are the SEVEN-TIER agreed output;
every tier pins the same table, which is what makes this a parity gate.
"""

from __future__ import annotations

import hashlib

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

PRELUDE = """import { StatefulSmartContract, assert } from "runar-lang";

class C extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

"""


def contract(body: str) -> str:
    return PRELUDE + body


# The item's probe: a helper containing an `if`, called with `v * 2n`.
IF_ARM = contract("""  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

# §6.3 control: the same program with the helper substituted by hand.
IF_ARM_MANUAL = contract("""  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let extra: bigint = 0n;
    if (a > 5n) {
      extra = a + 100n;
    } else {
      extra = a + 1n;
    }
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
""")

# N-051 oracle: differs from IF_ARM ONLY inside the then-arm (+200 not +100).
IF_ARM_200 = contract("""  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 200n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

# Same hazard through a ternary arm.
TERNARY_ARM = contract("""  private pay(v: bigint): void {
    const extra: bigint = v > 5n ? v + 100n : v + 1n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

TERNARY_ARM_MANUAL = contract("""  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    const extra: bigint = a > 5n ? a + 100n : a + 1n;
    this.addOutput(extra, this.count);
    assert(v >= 0n);
  }
}
""")

# Same hazard through a `for` body — `sub_context()` builds that too.
LOOP_BODY = contract("""  private pay(v: bigint): void {
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + v;
    }
    this.addOutput(acc, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

LOOP_BODY_MANUAL = contract("""  public go(v: bigint) {
    this.count = this.count + 1n;
    const a: bigint = v * 2n;
    let acc: bigint = 0n;
    for (let i = 0; i < 3; i++) {
      acc = acc + a;
    }
    this.addOutput(acc, this.count);
    assert(v >= 0n);
  }
}
""")

# Control: a helper with NO nested block at all. Must be byte-unchanged.
NO_IF = contract("""  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

# Control: the parameter is read at STATEMENT level inside the helper, and the
# `if` in the helper does not read it. Must be byte-unchanged.
STMT_LEVEL = contract("""  private pay(v: bigint): void {
    const extra: bigint = v + 100n;
    let bump: bigint = 0n;
    if (this.count > 5n) {
      bump = 1n;
    } else {
      bump = 2n;
    }
    this.addOutput(extra + bump, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v * 2n);
    assert(v >= 0n);
  }
}
""")

# Control: the argument IS the caller's own parameter (`this.pay(v)`), so
# caller-param and argument coincide and the WRONG lowering computed the right
# VALUE. It was still a different script — 701 B where Go/Rust emitted 703 —
# because the arm re-issued `load_param` instead of reading the alias slot.
PASSTHROUGH = contract("""  private pay(v: bigint): void {
    let extra: bigint = 0n;
    if (v > 5n) {
      extra = v + 100n;
    } else {
      extra = v + 1n;
    }
    this.addOutput(extra, this.count);
  }

  public go(v: bigint) {
    this.count = this.count + 1n;
    this.pay(v);
    assert(v >= 0n);
  }
}
""")

# label -> (script byte length, sha256 of the lowercase script hex)
SEVEN_TIER = {
    "if-arm": (702, "92db59e2c0e61df6dbeef8256d0c37ac1f74880f71d22bdd1e992fab9e257507"),
    "if-arm-manual": (702, "92db59e2c0e61df6dbeef8256d0c37ac1f74880f71d22bdd1e992fab9e257507"),
    "if-arm-200": (703, "7584c506d6b04e415c9036f8e345c749dc1661ef6dd13c7a05aa83597ddbd840"),
    "ternary-arm": (688, "ed951f38c72d41f09b0e20d9aeb1408693cbc7936f3e9ea7b6d34905ed6df613"),
    "ternary-arm-manual": (688, "ed951f38c72d41f09b0e20d9aeb1408693cbc7936f3e9ea7b6d34905ed6df613"),
    "loop-body": (695, "af13b9a1c80743a69ed0181c4bf227d99f632b18a2f8d71f51cf694b720e9590"),
    "loop-body-manual": (695, "af13b9a1c80743a69ed0181c4bf227d99f632b18a2f8d71f51cf694b720e9590"),
    "no-if": (680, "bfea7ecbf3196c7e4943227546da0918055d0c11548ba41ac4b45676f741f170"),
    "stmt-level": (698, "0b1e61517510b65cbdb2f18458df8c3d67b0decd116aabf592f3aef5e936a470"),
    "passthrough": (700, "1e7409174b2026df384f2d22e3baf6b8926ee9bfd4e17772f004bd7711a5f7e5"),
}

CASES = [
    ("if-arm", IF_ARM),
    ("if-arm-manual", IF_ARM_MANUAL),
    ("if-arm-200", IF_ARM_200),
    ("ternary-arm", TERNARY_ARM),
    ("ternary-arm-manual", TERNARY_ARM_MANUAL),
    ("loop-body", LOOP_BODY),
    ("loop-body-manual", LOOP_BODY_MANUAL),
    ("no-if", NO_IF),
    ("stmt-level", STMT_LEVEL),
    ("passthrough", PASSTHROUGH),
]


def compile_script_hex(source: str, disable_constant_folding: bool) -> str:
    result = compile_from_source_str_with_result(
        source, "C.runar.ts", disable_constant_folding=disable_constant_folding
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex.lower()


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize("label,source", CASES)
def test_seven_tier_script_for_inlined_param_alias(label, source, disable):
    hex_str = compile_script_hex(source, disable)
    want_len, want_sha = SEVEN_TIER[label]
    assert len(hex_str) // 2 == want_len, (
        f"{label} (disable_constant_folding={disable}): script length diverged "
        "from the seven-tier agreed output"
    )
    assert hashlib.sha256(hex_str.encode()).hexdigest() == want_sha, (
        f"{label} (disable_constant_folding={disable}): script bytes diverged "
        "from the seven-tier agreed output"
    )


@pytest.mark.parametrize("disable", [True, False])
@pytest.mark.parametrize(
    "kind,helper,manual",
    [
        ("if", IF_ARM, IF_ARM_MANUAL),
        ("ternary", TERNARY_ARM, TERNARY_ARM_MANUAL),
        ("for", LOOP_BODY, LOOP_BODY_MANUAL),
    ],
)
def test_helper_matches_manual_inline(kind, helper, manual, disable):
    """spec/semantics.md §6.3: inlining IS substitution, so the helper form and
    the hand-substituted program are the same program."""
    assert compile_script_hex(helper, disable) == compile_script_hex(manual, disable), (
        f"helper with a nested {kind} diverged from the hand-inlined source"
    )


@pytest.mark.parametrize("disable", [True, False])
def test_arm_reads_the_argument(disable):
    """The N-051 oracle, consulting no reference tier: two helper bodies that
    differ ONLY inside the arm must not compile to the same script."""
    assert compile_script_hex(IF_ARM, disable) != compile_script_hex(IF_ARM_200, disable)
