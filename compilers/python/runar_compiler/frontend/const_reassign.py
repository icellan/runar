"""N-342 -- a ``const`` local on the ``.runar.ts`` surface cannot be reassigned.

spec/grammar.md section 9: "``const`` variables cannot be reassigned." The
parser recorded ``mutable=False`` for ``const`` and nothing ever read it, so
``const s = 1n; s = s + x;`` compiled. Refused, with one sentence in all seven
tiers: ``x = e`` (and the compound forms the parser desugars to it), ``x++`` /
``++x`` / ``x--`` / ``--x``, and a ``const`` for-initializer, which the loop's
own ``i++`` then advances. Element writes (``x[0] = e``) are not touched.
Scoping follows blocks. Runs on the ``.runar.ts`` parse result only: other
surfaces spell immutability differently and several parsers record ``mutable``
as a constant.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    AssignmentStmt,
    ContractNode,
    DecrementExpr,
    Expression,
    ExpressionStmt,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    SourceLocation,
    Statement,
    VariableDeclStmt,
)
from runar_compiler.frontend.diagnostic import Diagnostic, Severity


def const_reassign_message(name: str) -> str:
    """The one sentence every tier emits for reassigning const ``name``."""
    return f"Cannot assign to '{name}' because it is a constant."


def _lookup(scopes: list[dict[str, bool]], name: str) -> bool | None:
    for scope in reversed(scopes):
        if name in scope:
            return scope[name]
    return None


def _check_target(target, scopes, loc: SourceLocation, out: list[Diagnostic]) -> None:
    if isinstance(target, Identifier) and _lookup(scopes, target.name) is False:
        out.append(Diagnostic(const_reassign_message(target.name), Severity.ERROR, loc))


def _check_simple(stmt, scopes, out: list[Diagnostic]) -> None:
    if isinstance(stmt, AssignmentStmt):
        _check_target(stmt.target, scopes, stmt.source_location, out)
    elif isinstance(stmt, ExpressionStmt) and isinstance(stmt.expr, (IncrementExpr, DecrementExpr)):
        _check_target(stmt.expr.operand, scopes, stmt.source_location, out)


def _walk(stmts: list[Statement], scopes: list[dict[str, bool]], out: list[Diagnostic]) -> None:
    here: dict[str, bool] = {}
    scopes.append(here)
    for stmt in stmts:
        if isinstance(stmt, VariableDeclStmt):
            here[stmt.name] = stmt.mutable
        elif isinstance(stmt, IfStmt):
            _walk(stmt.then, scopes, out)
            _walk(stmt.else_, scopes, out)
        elif isinstance(stmt, ForStmt):
            loop_scope: dict[str, bool] = {}
            if stmt.init is not None:
                loop_scope[stmt.init.name] = stmt.init.mutable
            scopes.append(loop_scope)
            _check_simple(stmt.update, scopes, out)
            _walk(stmt.body, scopes, out)
            scopes.pop()
        else:
            _check_simple(stmt, scopes, out)
    scopes.pop()


def check_const_reassignment(contract: ContractNode) -> list[Diagnostic]:
    """A diagnostic for every reassigned ``const`` local in ``contract``."""
    out: list[Diagnostic] = []
    _walk(contract.constructor.body, [], out)
    for method in contract.methods:
        _walk(method.body, [], out)
    return out
