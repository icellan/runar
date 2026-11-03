"""N-401 -- the validator's statement walkers cover a ``for`` loop's header.

Proves: ``_collect_method_calls`` (behind the recursion check) and
``_find_output_intrinsic`` (behind the no-addOutput-in-a-loop rule) visit all
three header slots of a ``for`` statement -- init, condition and update. A call
planted only in a header slot is collected, and an ``addOutput`` planted only
in a NESTED loop's header is found from the enclosing loop. The AST is
hand-built (mutated after parsing) because the for-update and literal-init
rules make these shapes unreachable from source today.

Does not prove: that any source program can reach these shapes today.
"""

from __future__ import annotations

import pytest

from runar_compiler.frontend.ast_nodes import (
    CallExpr,
    ExpressionStmt,
    ForStmt,
    PropertyAccessExpr,
)
from runar_compiler.frontend.parser_dispatch import parse_source
from runar_compiler.frontend.validator import _collect_method_calls, validate

PLAIN_SOURCE = """
class C extends SmartContract {
  readonly t: bigint;
  constructor(t: bigint) { super(t); this.t = t; }
  public m(a: bigint) {
    let s: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; i++) { s = s + a; }
    assert(s === this.t);
  }
}
"""

NESTED_SOURCE = """
class C extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public m(a: bigint) {
    let s: bigint = 0n;
    for (let i: bigint = 0n; i < 3n; i++) {
      for (let j: bigint = 0n; j < 3n; j++) { s = s + a; }
    }
    this.count = s;
  }
}
"""


def _this_call(name: str) -> CallExpr:
    return CallExpr(callee=PropertyAccessExpr(property=name), args=[])


def _plant(loop: ForStmt, slot: str, expr: CallExpr) -> None:
    if slot == "init":
        loop.init.init = expr
    elif slot == "condition":
        loop.condition = expr
    else:
        loop.update = ExpressionStmt(expr=expr, source_location=loop.source_location)


def _parse(source: str):
    result = parse_source(source, "C.runar.ts")
    assert result.errors == [], result.error_strings()
    return result.contract


@pytest.mark.parametrize("slot", ["init", "condition", "update"])
def test_collect_method_calls_visits_for_header_slot(slot: str):
    contract = _parse(PLAIN_SOURCE)
    loops = [s for s in contract.methods[0].body if isinstance(s, ForStmt)]
    assert len(loops) == 1
    _plant(loops[0], slot, _this_call("m"))
    calls: set[str] = set()
    _collect_method_calls(contract.methods[0].body, calls, True)
    assert "m" in calls, f"collector did not visit the for-loop {slot}; got {calls}"


@pytest.mark.parametrize("slot", ["init", "condition", "update"])
def test_output_intrinsic_search_visits_nested_for_header_slot(slot: str):
    contract = _parse(NESTED_SOURCE)
    outer = [s for s in contract.methods[0].body if isinstance(s, ForStmt)]
    assert len(outer) == 1
    inner = [s for s in outer[0].body if isinstance(s, ForStmt)]
    assert len(inner) == 1
    _plant(inner[0], slot, _this_call("addOutput"))
    val = validate(contract)
    assert any("Output intrinsic 'addOutput'" in d.message for d in val.errors), (
        f"addOutput in nested for-loop {slot} was not found; got {[d.message for d in val.errors]}"
    )
