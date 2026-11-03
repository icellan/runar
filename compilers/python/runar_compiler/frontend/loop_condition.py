"""N-115 -- normalise a reversed loop comparison to the canonical spelling.

Every later pass reads a loop's iterator off the LEFT-hand side of its
condition (W4, ``_validate_for_condition_tests_iterator``) and its bound off
the right. ``10 > i`` says the same thing as ``i < 10``, so the parser
rewrites it once instead of every pass learning a second spelling::

    N >  i  ->  i <  N        N <  i  ->  i >  N
    N >= i  ->  i <= N        N <= i  ->  i >= N

The rule, identical in all seven tiers: the condition is a ``<``/``<=``/``>``/
``>=`` comparison, its RIGHT operand is the loop variable, and its LEFT operand
is not -> swap the operands and mirror the operator. Nothing else is touched,
so the W4 refusals (N40, N41) and the direction rule (N42) keep firing.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    BinaryExpr,
    ContractNode,
    Expression,
    ForStmt,
    Identifier,
    IfStmt,
    Statement,
)

_MIRRORED = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}


def normalize_loop_condition(cond: Expression | None, iter_name: str) -> Expression | None:
    """The canonical form of ``cond`` for a loop over ``iter_name`` (or ``cond``)."""
    if not isinstance(cond, BinaryExpr) or cond.op not in _MIRRORED:
        return cond

    def is_iter(e: Expression) -> bool:
        return isinstance(e, Identifier) and e.name == iter_name

    if not is_iter(cond.right) or is_iter(cond.left):
        return cond
    return BinaryExpr(op=_MIRRORED[cond.op], left=cond.right, right=cond.left)


def _normalize_statements(stmts: list[Statement]) -> None:
    for stmt in stmts:
        if isinstance(stmt, ForStmt):
            if stmt.init is not None:
                stmt.condition = normalize_loop_condition(stmt.condition, stmt.init.name)
            _normalize_statements(stmt.body)
        elif isinstance(stmt, IfStmt):
            _normalize_statements(stmt.then)
            _normalize_statements(stmt.else_)


def normalize_loop_conditions(contract: ContractNode) -> None:
    """Rewrite every loop condition in ``contract`` to its canonical spelling."""
    _normalize_statements(contract.constructor.body)
    for method in contract.methods:
        _normalize_statements(method.body)
