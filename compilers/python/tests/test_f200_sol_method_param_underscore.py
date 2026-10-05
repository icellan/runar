"""F-200 (CL-BUG-208..213) — .runar.sol leading-underscore stripping applies
to CONSTRUCTOR params only.

``parse_sol_params`` used to strip a leading ``_`` from every parameter, so a
METHOD param ``_x`` was declared as ``x`` while its body still read ``_x``.
Two failure shapes followed:

* unbound: ``function check(bigint _x) public { require(_x == target); }``
  failed typecheck with "Undefined variable '_x'" (TS compiles it);
* silent: ``function inc(bigint _count) public { count++; }`` declared a
  param named ``count`` that shadowed the property, so the bare ``count++``
  bumped the param and the state write was dropped — a different script.

The rule is the TS reference's (01-parse-sol.ts): ``parseConstructor`` strips
``_`` and renames the body; ``parseFunction`` keeps param names verbatim.

What this proves: in this tier, method params keep their ``_`` name, the
constructor still strips it, and both shapes compile (fold-ON CLI default)
to the TS reference bytes (sha256-pinned, same pins as
conformance/negatives/sol-method-param-underscore-parity.test.ts).
What it does NOT prove: other tiers (the 7-tier pin lives in that conformance
test) or on-chain spend behaviour of the bytes.
"""
from __future__ import annotations

import hashlib

from runar_compiler.compiler import compile_from_source_str_with_result
from runar_compiler.frontend.ast_nodes import ExpressionStmt, IncrementExpr, PropertyAccessExpr
from runar_compiler.frontend.parser_dispatch import parse_source

UNBOUND = """\
pragma runar ^0.1.0;

contract F200Unbound is SmartContract {
    bigint immutable target;

    constructor(bigint _target) {
        target = _target;
    }

    function check(bigint _x) public {
        require(_x == target);
    }
}
"""

SILENT = """\
pragma runar ^0.1.0;

contract F200Silent is StatefulSmartContract {
    bigint count;

    constructor(bigint _count) {
        count = _count;
    }

    function inc(bigint _count) public {
        count++;
    }
}
"""

UNBOUND_HEX = "009c"
SILENT_SHA256 = "3676c0b9030628828837696cad74c710bb225d151f5ba822be8b2ed302e3a342"


def _method(src: str, file: str, name: str):
    result = parse_source(src, file)
    assert result.errors == [], result.error_strings()
    return next(m for m in result.contract.methods if m.name == name), result.contract


def _hex(src: str, file: str) -> str:
    result = compile_from_source_str_with_result(src, file)
    assert result.success, [d.message for d in result.diagnostics]
    return result.script_hex


def test_method_param_keeps_underscore_and_constructor_strips():
    m, c = _method(UNBOUND, "F200Unbound.runar.sol", "check")
    assert [p.name for p in m.params] == ["_x"]
    assert [p.name for p in c.constructor.params] == ["target"]


def test_unbound_shape_compiles_to_ts_bytes():
    assert _hex(UNBOUND, "F200Unbound.runar.sol") == UNBOUND_HEX


def test_silent_shape_writes_state():
    m, _ = _method(SILENT, "F200Silent.runar.sol", "inc")
    assert [p.name for p in m.params] == ["_count"]
    stmt = m.body[0]
    assert isinstance(stmt, ExpressionStmt) and isinstance(stmt.expr, IncrementExpr)
    assert isinstance(stmt.expr.operand, PropertyAccessExpr)
    assert hashlib.sha256(_hex(SILENT, "F200Silent.runar.sol").encode()).hexdigest() == SILENT_SHA256
