"""DoS-bound input limits + typed errors for the Python compiler frontend.

Mirrors ``InputLimits`` from ``packages/runar-ir-schema/src/input-limits.ts``.
See ``compilers/go/frontend/input_limits.go`` for the reference shape.
"""

from __future__ import annotations

import functools
import sys
import threading
from typing import TYPE_CHECKING, Callable

from runar_compiler.frontend import ast_nodes as _ast

if TYPE_CHECKING:
    from runar_compiler.frontend.ast_nodes import ContractNode, SourceLocation
    from runar_compiler.frontend.parser_dispatch import ParseResult

# Mirrors ``InputLimits.MAX_SOURCE_BYTES`` (4 MiB) from the TS schema package.
# Rúnar source files larger than this are rejected at the parser entry
# point (``parse_source``) BEFORE the tokenizer touches the input.
# BUG-008 follow-up.
MAX_SOURCE_BYTES: int = 4 * 1024 * 1024

# Mirrors ``InputLimits.MAX_SOURCE_NESTING`` (128) from
# packages/runar-ir-schema/src/input-limits.ts, which defines the two measures
# it bounds: (A) parse nesting, counted by every parser through
# :class:`NestingCounter`, and (B) AST nesting, checked on the finished tree by
# :func:`ast_nesting_violation`. F-213.
MAX_SOURCE_NESTING: int = 128

# Mirrors ``InputLimits.MAX_CALL_DEPTH`` (128) from
# packages/runar-ir-schema/src/input-limits.ts (N-180). The call depth of a
# method is 0 if it calls no contract method, else 1 + the largest call depth
# among the contract methods it calls. Private methods are inlined at every call
# site, so this is the inlining depth; the validator refuses a method that does
# not reach a call cycle and sits deeper than this, naming the first such method
# in declaration order with :func:`call_depth_message`.
MAX_CALL_DEPTH: int = 128


def call_depth_message(method: str) -> str:
    """The one diagnostic every tier emits for a call chain past MAX_CALL_DEPTH."""
    return f"call depth of method '{method}' exceeds MAX_CALL_DEPTH (limit={MAX_CALL_DEPTH})"


class SourceSizeExceededError(Exception):
    """Raised when a source payload exceeds :data:`MAX_SOURCE_BYTES` at a
    public parser entry point. Distinct typed exception so callers can
    distinguish DoS-bound rejection from generic syntax errors."""

    def __init__(self, limit: int, actual: int) -> None:
        super().__init__(
            f"source exceeds MAX_SOURCE_BYTES (limit={limit}, actual={actual})"
        )
        self.limit = limit
        self.actual = actual


def assert_source_bytes_under_limit(source: str) -> None:
    """Raise :class:`SourceSizeExceededError` if ``source`` (encoded as
    UTF-8) exceeds :data:`MAX_SOURCE_BYTES`."""
    n = len(source.encode("utf-8"))
    if n > MAX_SOURCE_BYTES:
        raise SourceSizeExceededError(limit=MAX_SOURCE_BYTES, actual=n)


# ---------------------------------------------------------------------------
# F-213: source nesting limit
# ---------------------------------------------------------------------------

#: The one diagnostic every tier emits for an over-nested source.
SOURCE_NESTING_MESSAGE = (
    f"source nesting depth exceeds MAX_SOURCE_NESTING (limit={MAX_SOURCE_NESTING})"
)


class SourceNestingError(Exception):
    """Raised by :class:`NestingCounter` to unwind a parser at the limit.

    Deliberately NOT a ``ValueError``: the parsers catch ``ValueError`` for
    speculative parses and error recovery, and this must get past all of them
    to :func:`with_nesting_limit`."""

    def __init__(self, loc: "SourceLocation | None" = None) -> None:
        super().__init__(SOURCE_NESTING_MESSAGE)
        self.loc = loc


class NestingCounter:
    """Measure (A): the parse-nesting counter.

    A parser wraps each counted construct (a statement, a full-expression
    parse, a prefix-unary operand, a nested type argument) in
    ``with self._nest.nested(self.loc):``. Going past the limit raises
    :class:`SourceNestingError` (located by calling ``loc_fn``), so parser
    recursion never gets deeper than MAX_SOURCE_NESTING counted levels.
    """

    __slots__ = ("depth", "_loc_fn")

    def __init__(self) -> None:
        self.depth = 0
        self._loc_fn: "Callable[[], SourceLocation] | None" = None

    def nested(self, loc_fn: "Callable[[], SourceLocation] | None" = None) -> "NestingCounter":
        self._loc_fn = loc_fn
        return self

    def __enter__(self) -> "NestingCounter":
        if self.depth >= MAX_SOURCE_NESTING:
            loc_fn = self._loc_fn
            raise SourceNestingError(loc_fn() if loc_fn is not None else None)
        self.depth += 1
        return self

    def __exit__(self, *exc: object) -> None:
        self.depth -= 1


def _expr_children(e: object) -> list:
    a = _ast  # short alias for the isinstance chain below
    if isinstance(e, a.BinaryExpr):
        return [e.left, e.right]
    if isinstance(e, (a.UnaryExpr, a.IncrementExpr, a.DecrementExpr)):
        return [e.operand]
    if isinstance(e, a.CallExpr):
        return [e.callee, *e.args]
    if isinstance(e, a.MemberExpr):
        return [e.object]
    if isinstance(e, a.TernaryExpr):
        return [e.condition, e.consequent, e.alternate]
    if isinstance(e, a.IndexAccessExpr):
        return [e.object, e.index]
    if isinstance(e, a.ArrayLiteralExpr):
        return list(e.elements)
    return []


def _expr_too_deep(e: object, level: int) -> bool:
    """True iff some node of ``e``, sitting at nesting ``level``, is deeper
    than the limit. Recurses at most MAX_SOURCE_NESTING + 1 frames: it stops
    the moment ``level`` passes the limit."""
    if level > MAX_SOURCE_NESTING:
        return True
    for c in _expr_children(e):
        if c is not None and _expr_too_deep(c, level + 1):
            return True
    return False


def _type_too_deep(t: object) -> bool:
    """Type nesting: a fixed-array type is one deeper than its element."""
    depth = 0
    cur = t
    while cur is not None:
        depth += 1
        if depth > MAX_SOURCE_NESTING:
            return True
        cur = cur.element if isinstance(cur, _ast.FixedArrayType) else None
    return False


def _stmts_too_deep(stmts: list, level: int):
    """The statement whose subtree breaks the limit, or ``None``."""
    a = _ast
    for st in stmts:
        if st is None:
            continue
        if level > MAX_SOURCE_NESTING:
            return st
        if isinstance(st, a.VariableDeclStmt) and _type_too_deep(st.type):
            return st
        slots: list = []
        nested: list = []
        if isinstance(st, a.VariableDeclStmt):
            slots.append(st.init)
        elif isinstance(st, a.AssignmentStmt):
            slots += [st.target, st.value]
        elif isinstance(st, a.ExpressionStmt):
            slots.append(st.expr)
        elif isinstance(st, a.ReturnStmt):
            slots.append(st.value)
        elif isinstance(st, a.IfStmt):
            slots.append(st.condition)
            nested.append(st.then)
            if st.else_:
                nested.append(st.else_)
        elif isinstance(st, a.ForStmt):
            slots.append(st.condition)
            nested += [[st.init, st.update], st.body]
        for e in slots:
            if e is not None and _expr_too_deep(e, level + 1):
                return st
        for lst in nested:
            bad = _stmts_too_deep(lst, level + 1)
            if bad is not None:
                return bad
    return None


def ast_nesting_violation(contract: "ContractNode"):
    """Measure (B): AST nesting. Returns ``None`` when the contract is within
    the limit, else the location to report (possibly an empty one when the
    offending node carries none). Bounded recursion, safe on any depth."""
    for p in contract.properties:
        if _type_too_deep(p.type):
            return p.source_location
        if p.initializer is not None and _expr_too_deep(p.initializer, 1):
            return p.source_location
    methods = [contract.constructor, *contract.methods] if contract.constructor else list(contract.methods)
    for m in methods:
        if any(_type_too_deep(p.type) for p in m.params):
            return m.source_location
        bad = _stmts_too_deep(m.body, 1)
        if bad is not None:
            return bad.source_location
    return None


def assert_body_nesting(body: list) -> None:
    """Raise :class:`SourceNestingError` when a method body fails measure (B):
    the per-body half of :func:`assert_ast_nesting`, for a parser whose
    recursive post-pass runs before the ContractNode exists."""
    bad = _stmts_too_deep(body, 1)
    if bad is not None:
        raise SourceNestingError(bad.source_location)


def assert_ast_nesting(contract: "ContractNode") -> None:
    """Raise :class:`SourceNestingError` when ``contract`` fails measure (B).

    For a parser that runs a recursive pass over its own AST before returning
    (e.g. a property rewrite): calling this first keeps that pass off a tree
    deeper than the limit."""
    at = ast_nesting_violation(contract)
    if at is not None:
        raise SourceNestingError(at)


# The CPython recursion limit while a source compiles (F-213). The hand-written
# parsers recurse ~15-17 Python frames per counted (A) level (statement ->
# expression -> ternary -> or -> and -> ... -> unary -> postfix -> primary), so
# CPython's default of 1000 refused 64 nested parens. Measured with Python 3.14,
# end to end through compile_from_source_collecting_warnings from a bare
# interpreter, the smallest recursionlimit that compiles each at-limit boundary
# shape (126 parens / 126 nested ifs / 63 unary minus / 127-term chain) on all
# nine surfaces: worst 2178 (126 parens on .runar.rb / .runar.py), 1286 for
# the ifs, <= 1170 for unary, 266 for the chain; 125 nested abs() calls and 62
# nested ternaries need less (2034, 646). 6000 is ~2.75x the worst, so a
# caller already deep in its own stack (pytest, an embedding app) still has
# room. CPython 3.11+ runs Python-to-Python calls without consuming C stack, so
# there the raise cannot overflow the thread stack and recursion past it is a
# catchable RecursionError (see with_nesting_limit). On 3.10 (the
# requires-python floor) Python frames still use C stack, so a compile at this
# depth inside a small-stack thread is not covered by that argument.
COMPILE_RECURSION_LIMIT = 6000

_recursion_lock = threading.Lock()
_recursion_users = 0
_recursion_saved = 0


class recursion_headroom:
    """Context manager / decorator: run with ``sys.getrecursionlimit()`` at
    least :data:`COMPILE_RECURSION_LIMIT`, restoring the caller's limit when
    the last concurrent user leaves (the limit is process-global, so nested
    and concurrent compiles share one raise)."""

    def __enter__(self) -> None:
        global _recursion_users, _recursion_saved
        with _recursion_lock:
            if _recursion_users == 0:
                _recursion_saved = sys.getrecursionlimit()
                if _recursion_saved < COMPILE_RECURSION_LIMIT:
                    sys.setrecursionlimit(COMPILE_RECURSION_LIMIT)
            _recursion_users += 1

    def __exit__(self, *exc: object) -> None:
        global _recursion_users
        with _recursion_lock:
            _recursion_users -= 1
            if _recursion_users == 0:
                sys.setrecursionlimit(_recursion_saved)

    def __call__(self, fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            with recursion_headroom():
                return fn(*args, **kwargs)

        return wrapper


def _nesting_error(loc: "SourceLocation | None") -> "ParseResult":
    from runar_compiler.frontend.diagnostic import Diagnostic, Severity
    from runar_compiler.frontend.parser_dispatch import ParseResult

    return ParseResult(errors=[Diagnostic(message=SOURCE_NESTING_MESSAGE, severity=Severity.ERROR, loc=loc)])


def with_nesting_limit(file_name: str, run: "Callable[[], ParseResult]") -> "ParseResult":
    """Run a parser and apply both nesting measures to it (the TS reference's
    ``withNestingLimit``).

    A :class:`SourceNestingError` from measure (A) becomes the shared
    diagnostic, and so does a ``RecursionError``: with (A) bounding every
    parser's own recursion, the only way to exhaust the (raised) recursion
    limit is a tree thousands of levels deep -- far past the limit, built by a
    parser loop -- met by a recursive pass inside the parser (e.g. a property
    rewrite) before measure (B) ran. On success, measure (B) is checked before
    the AST is handed back.
    """
    from runar_compiler.frontend.diagnostic import Diagnostic, Severity
    from runar_compiler.frontend.parser_dispatch import ParseResult

    with recursion_headroom():
        try:
            result = run()
        except SourceNestingError as e:
            return _nesting_error(e.loc)
        except RecursionError:
            return _nesting_error(_ast.SourceLocation(file=file_name, line=1, column=0))
        if result.contract is not None:
            at = ast_nesting_violation(result.contract)
            if at is not None:
                return ParseResult(errors=[
                    *result.errors,
                    Diagnostic(message=SOURCE_NESTING_MESSAGE, severity=Severity.ERROR, loc=at),
                ])
    return result
