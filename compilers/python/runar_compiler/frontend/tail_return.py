"""N-511: tail values on the surfaces whose trailing expression IS the value.

On .runar.rs / .runar.move (with a declared return type) and .runar.rb
(private helpers) the trailing expression statement becomes an explicit
return, recursively through the arms of a trailing if/else
(``if c { x } else { 0 }``) when ``into_arms``. The return keeps the
expression statement's own source location, so the lowered ANF is unchanged;
the type checker then needs no tail-value heuristic.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import ExpressionStmt, ForStmt, IfStmt, ReturnStmt


def promote_tail_returns(stmts: list, into_arms: bool = True) -> None:
    if not stmts:
        return
    last = stmts[-1]
    if isinstance(last, ExpressionStmt):
        stmts[-1] = ReturnStmt(value=last.expr, source_location=getattr(last, "source_location", None))
    elif into_arms and isinstance(last, IfStmt) and last.else_:
        promote_tail_returns(last.then, True)
        promote_tail_returns(last.else_, True)


def has_value_return(stmts: list) -> bool:
    """Whether a ``return <value>`` appears anywhere in the list."""
    for s in stmts:
        if isinstance(s, ReturnStmt):
            if s.value is not None:
                return True
        elif isinstance(s, IfStmt):
            if has_value_return(s.then) or has_value_return(s.else_ or []):
                return True
        elif isinstance(s, ForStmt):
            if has_value_return(s.body):
                return True
    return False
