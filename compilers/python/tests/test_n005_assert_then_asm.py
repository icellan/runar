"""N-005 — an assert that is not the method's last binding must be lowered
with OP_VERIFY. Port of the reference tier's case in
packages/runar-compiler/src/__tests__/asm-surface.test.ts.

Stack lowering treated the LAST assert of a public method as terminal (its
value left as the script result) even when a terminal asm() followed it. The
asm pushed OP_1, the end-of-method cleanup NIPped the comparison away, and the
method compiled to 012a9c5177 (<42> OP_NUMEQUAL OP_1 OP_NIP): spendable with
ANY x. The hand-derived fixed script is 012a9d51 (<42> OP_NUMEQUALVERIFY OP_1).

Proves: this tier's bytes for the shape in both fold modes, and that a truly
final assert still stays the method result. Does NOT prove on-chain behaviour
— the Spend-engine proof for all seven tiers is
packages/runar-testing/src/__tests__/n005-assert-then-asm-spend.test.ts.
"""

from __future__ import annotations

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result

ASSERT_THEN_ASM = """import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AssertThenAsm extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === 42n);
    asm({ body: '51', in_arity: 0, out_arity: 1 });
  }
}
"""

ASM_THEN_ASSERT = """import { UnsafeSmartContract, assert, asm } from 'runar-lang';

class AsmThenAssert extends UnsafeSmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    asm({ body: '51', in_arity: 0, out_arity: 1 });
    assert(x === 42n);
  }
}
"""


def _hex(source: str, disable: bool) -> str:
    result = compile_from_source_str_with_result(
        source, "AssertThenAsm.runar.ts", disable_constant_folding=disable,
    )
    if not result.success:
        msgs = "; ".join(d.message for d in result.diagnostics)
        pytest.fail(f"compilation failed: {msgs}")
    return result.script_hex


@pytest.mark.parametrize("disable", [True, False])
def test_assert_before_terminal_asm_is_verified(disable: bool) -> None:
    got = _hex(ASSERT_THEN_ASM, disable)
    assert got != "012a9c5177", "assert left unenforced (pre-fix bytes)"
    assert got == "012a9d51"  # <42> OP_NUMEQUALVERIFY OP_1


def test_final_assert_stays_the_result() -> None:
    # OP_1 OP_SWAP <42> OP_NUMEQUAL (terminal, no OP_VERIFY) OP_NIP
    assert _hex(ASM_THEN_ASSERT, True) == "517c012a9c77"
