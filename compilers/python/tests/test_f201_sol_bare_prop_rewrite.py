"""F-201 (CL-BUG-208..213) — .runar.sol bare property references inside
``++`` / ``--`` / member expressions.

Solidity lets a method name a state variable without ``this.``. The parser
rewrites such bare identifiers to ``PropertyAccessExpr``, but before this fix
``_rewrite_bare_props`` had no branch for ``IncrementExpr``, ``DecrementExpr``
or ``MemberExpr``: their operand / object kept a bare ``Identifier``. So in a
StatefulSmartContract ``count++;`` compiled to a script that bumps a phantom
local and carries the OLD state into the continuation output — a silent
miscompile (the TS, Go, Rust, Zig and Ruby tiers all write the state).

The rule is the TS reference's (01-parse-sol.ts ``resolvePropertyAccess``):
recurse into the operand of ``increment_expr`` / ``decrement_expr`` and the
object of ``member_expr``; a method parameter or an in-scope local of the same
name shadows the property and is left alone.

What this proves: in this tier, the canonical Counter written with bare
``count++`` / ``++count`` / ``count += 1`` / ``count--`` / ``--count`` compiles
(fold OFF) byte-identically to the stateful-counter conformance golden, which
all seven tiers already produce from the ``this.count`` form; the operands are
rewritten to property accesses at the AST level, ``MemberExpr`` objects are
rewritten, and a same-named parameter or local still shadows the property.
What it does NOT prove: other tiers (the 7-tier byte parity and the
state-advances execution check were run separately and are recorded in the
F-201 remediation log); F-200 (leading-underscore stripping of METHOD params,
a separate item in the same file).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.ast_nodes import (
    DecrementExpr,
    ExpressionStmt,
    Identifier,
    IncrementExpr,
    MemberExpr,
    PropertyAccessExpr,
)
from runar_compiler.frontend.parser_dispatch import parse_source

FILE = "Counter.runar.sol"
GOLDEN = (
    Path(__file__).resolve().parents[3] / "conformance" / "tests" / "stateful-counter" / "expected-script.hex"
).read_text().strip()


def _counter(increment: str, decrement: str) -> str:
    return f"""\
pragma runar ^0.1.0;

contract Counter is StatefulSmartContract {{
    bigint count;

    constructor(bigint _count) {{
        count = _count;
    }}

    function increment() public {{
        {increment}
    }}

    function decrement() public {{
        require(count > 0);
        {decrement}
    }}
}}
"""


VARIANTS = {
    "postfix": _counter("count++;", "count--;"),
    "prefix": _counter("++count;", "--count;"),
    "compound": _counter("count += 1;", "count -= 1;"),
}


@pytest.mark.parametrize("name", list(VARIANTS))
def test_bare_counter_compiles_to_the_stateful_counter_golden(name: str) -> None:
    res = compile_from_source_str_with_result(VARIANTS[name], FILE, disable_constant_folding=True)
    assert res.success, [d.message for d in res.diagnostics]
    assert res.script_hex.lower() == GOLDEN


def _method_body(src: str, method: str):
    result = parse_source(src, FILE)
    assert result.errors == [], result.error_strings()
    return next(m for m in result.contract.methods if m.name == method).body


@pytest.mark.parametrize(
    "stmt, node",
    [("count++;", IncrementExpr), ("++count;", IncrementExpr), ("count--;", DecrementExpr), ("--count;", DecrementExpr)],
)
def test_update_operand_is_rewritten_to_property_access(stmt: str, node: type) -> None:
    body = _method_body(_counter(stmt, "count--;"), "increment")
    expr = body[0].expr
    assert isinstance(body[0], ExpressionStmt) and isinstance(expr, node)
    assert expr.operand == PropertyAccessExpr(property="count")


def test_member_object_is_rewritten_to_property_access() -> None:
    body = _method_body(_counter("require(count.length > 0);", "count--;"), "increment")
    member = body[0].expr.args[0].left
    assert member == MemberExpr(object=PropertyAccessExpr(property="count"), property="length")


def test_parameter_shadows_the_property() -> None:
    src = _counter("count++;", "count--;").replace("function increment()", "function increment(bigint count)")
    body = _method_body(src, "increment")
    assert body[0].expr.operand == Identifier(name="count")


def test_local_shadows_the_property() -> None:
    body = _method_body(_counter("bigint count = 5; count++;", "count--;"), "increment")
    assert body[1].expr.operand == Identifier(name="count")
    # ... but the property is still reached in a method without the local.
    assert _method_body(_counter("bigint count = 5; count++;", "count--;"), "decrement")[1].expr.operand == (
        PropertyAccessExpr(property="count")
    )
