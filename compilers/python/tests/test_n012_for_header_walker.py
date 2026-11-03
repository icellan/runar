"""N-012 -- the validator's expression walker covers a ``for`` loop's header.

Proves: ``_walk_expressions_in_stmt`` (the walker behind the asm() gate) visits
all three header slots of a ``for`` statement -- init, condition and update --
so an ``asm(...)`` call planted in any of them in a non-Unsafe contract is
refused. The AST is hand-built (mutated after parsing) because the for-update
and literal-init rules make these shapes unreachable from source today.

Does not prove: that any source program can reach this; only that a future
loosening of those rules cannot reopen the asm gate through the walker.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.ast_nodes import CallExpr, ExpressionStmt, ForStmt, Identifier
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import validate

SOURCE = """
class C extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public verify(a: bigint) {
    let s: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
    assert(s === this.t);
  }
}
"""

DIAG = "'asm' is only available in contracts extending UnsafeSmartContract"


def _asm_call() -> CallExpr:
    return CallExpr(callee=Identifier(name="asm"), args=[])


@pytest.mark.parametrize("slot", ["init", "condition", "update"])
def test_asm_in_for_header_slot_is_refused(slot: str):
    result = parse_source(SOURCE, "C.runar.ts")
    assert result.errors == [], result.error_strings()
    contract = result.contract
    loops = [s for s in contract.methods[0].body if isinstance(s, ForStmt)]
    assert len(loops) == 1
    loop = loops[0]
    if slot == "init":
        loop.init.init = _asm_call()
    elif slot == "condition":
        loop.condition = _asm_call()
    else:
        loop.update = ExpressionStmt(expr=_asm_call(), source_location=loop.source_location)

    val = validate(contract)
    assert any(DIAG in d.message for d in val.errors), (
        f"asm() in for-loop {slot} was not refused; got {[d.message for d in val.errors]}"
    )
