"""D26: a block-height locktime gate must pin the locktime domain.

Mirrors packages/runar-compiler/src/passes/locktime-domain.ts (same rule and
text in all seven tiers; read that file for the full rationale).

Consensus reads an nLockTime below 500,000,000 as a block height and one at or
above it as a Unix timestamp, so ``extractLocktime(p) >= H`` for a height H is
passed at once by any timestamp-domain locktime.

A GATE is a lower-bound compare on a locktime read (``extractLocktime(...)``,
``currentBlockHeight()``, a local bound to one, or a private helper's parameter
a call passes one: a DIRECT read), unless the other side is a timestamp-domain
literal (it pins the domain itself) or the vacuous ``>= 0``. A value DERIVED
from a read (arithmetic, bitwise, shift,
unary ``-``/``~``, a ternary arm, a builtin taking a read, or a local some of
whose bindings are not direct reads) is a gate under any lower bound and never
a pin. A PIN is an asserted domain bound on a direct read, the asserted
condition itself or a top-level ``&&`` conjunct.

The rule is PER PATH, with D18's walk shape (continuation_rules.py) and two
bits, gate seen / pin seen: every path through a public method that carries a
gate must also carry a pin. The --ir path re-derives it in
ir/locktime_domain.py.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
    BigIntLiteral,
    BinaryExpr,
    CallExpr,
    DecrementExpr,
    ExpressionStmt,
    ForStmt,
    Identifier,
    IfStmt,
    IncrementExpr,
    IndexAccessExpr,
    MemberExpr,
    PropertyAccessExpr,
    ReturnStmt,
    TernaryExpr,
    UnaryExpr,
    VariableDeclStmt,
)


def locktime_domain_message(method: str) -> str:
    """D26: the shared error text."""
    return (
        f"method '{method}' compares extractLocktime against a lower bound without pinning the locktime domain: "
        "consensus reads an nLockTime of 500000000 or more as a Unix timestamp, so on that path any such locktime "
        "passes a block-height gate at once. On every path that compares, assert(extractLocktime(preimage) < "
        "500000000n) for a block-height gate, or assert(extractLocktime(preimage) >= 500000000n) for a timestamp gate"
    )


# The first nLockTime value consensus reads as a Unix timestamp.
LOCKTIME_THRESHOLD = 500000000

# Path-state bits: gate seen / pin seen.
G = 1
P = 2
FRESH = frozenset({0})


def unpinned(states) -> bool:
    return any(x & G and not x & P for x in states)


def or_all(states: frozenset[int], bits: int) -> frozenset[int]:
    return frozenset(x | bits for x in states)


def compose(a: frozenset[int], b: frozenset[int]) -> frozenset[int]:
    return frozenset(x | y for x in a for y in b)


_FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<="}


def classify(op: str, other: int | None) -> str:
    """Classify ``lt <op> other`` (the locktime read on the left); ``other`` is
    the literal's value, or None when it is not a bigint literal."""
    if op in (">=", ">"):
        # `>= 0n` is vacuous (every locktime passes it): no gate. Only literal
        # 0: a negative bound is a negation in source but may be a literal in IR.
        if op == ">=" and other == 0:
            return "none"
        ts = other is not None and (
            other >= LOCKTIME_THRESHOLD if op == ">=" else other >= LOCKTIME_THRESHOLD - 1
        )
        return "pin" if ts else "gate"
    if other is None:
        return "none"
    if op == "<":
        height = 0 < other <= LOCKTIME_THRESHOLD
    else:
        height = 0 <= other < LOCKTIME_THRESHOLD
    return "pin" if height else "none"


# Taint level of a value: not a locktime read / a direct read / derived from one.
NONE = 0
DIRECT = 1
DERIVED = 2
# Operators whose result derives from their operands (compares and logic do not).
PROPAGATE = frozenset({"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"})
PROPAGATE_UNARY = frozenset({"-", "~"})


def solve_taint(binds, tainted, direct) -> dict[str, int]:
    """Taint of a set of names from their bindings, deterministic and
    order-blind: least fixpoint for the tainted set, then greatest fixpoint
    (within it) for the names all of whose bindings are direct reads."""
    t: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, b in binds:
            if name not in t and tainted(b, t):
                t.add(name)
                changed = True
    d = set(t)
    changed = True
    while changed:
        changed = False
        for name, b in binds:
            if name in d and not direct(b, d):
                d.discard(name)
                changed = True
    return {n: (DIRECT if n in d else DERIVED) for n in t}


def classify_compare(op, left, right, level, literal) -> str:
    """Each tainted side is read as the left one. A direct read classifies
    against the other side's literal; a derived value is a gate under any
    lower bound and never a pin. A gate on either side wins over a pin."""
    if op not in _FLIP:
        return "none"

    def side(lv: int, o: str, other) -> str:
        if lv == DIRECT:
            return classify(o, literal(other))
        if lv == DERIVED:
            return "gate" if o in (">=", ">") else "none"
        return "none"

    a = side(level(left), op, right)
    b = side(level(right), _FLIP[op], left)
    if a == "gate" or b == "gate":
        return "gate"
    return "pin" if a == "pin" or b == "pin" else "none"


def helper_params(params, arg_levels) -> tuple[dict[str, int], tuple]:
    """A helper's tainted parameters from its call's argument levels, and the
    cache key signature (the level of every parameter)."""
    out: dict[str, int] = {}
    for i, p in enumerate(params):
        lv = arg_levels[i] if i < len(arg_levels) else NONE
        if lv != NONE:
            out[p.name] = lv
    return out, tuple(out.get(p.name, NONE) for p in params)


# ---------------------------------------------------------------------------
# Source path
# ---------------------------------------------------------------------------


def _is_call_to(e, name: str) -> bool:
    return isinstance(e, CallExpr) and isinstance(e.callee, Identifier) and e.callee.name == name


def _is_read(e) -> bool:
    return _is_call_to(e, "extractLocktime") or _is_call_to(e, "currentBlockHeight")


def contract_reads_locktime(contract) -> bool:
    """Prefilter: does any method call extractLocktime or currentBlockHeight?
    Without a read there is no gate, so the path walk is skipped."""

    def seen(node) -> bool:
        if _is_read(node):
            return True
        for v in vars(node).values():
            if isinstance(v, list):
                if any(hasattr(x, "__dict__") and seen(x) for x in v):
                    return True
            elif hasattr(v, "__dict__") and not isinstance(v, type) and seen(v):
                return True
        return False

    return any(seen(st) for m in contract.methods for st in m.body or [])


def has_unpinned_locktime_gate(contract, method) -> bool:
    """D26 (source path): some path through public ``method`` carries an
    unpinned gate."""
    return unpinned(_SourceGates(contract).exits(method, {}))


def _expr_level(e, names: dict[str, int]) -> int:
    if e is None:
        return NONE
    if _is_read(e):
        return DIRECT

    def any_(*xs) -> int:
        return DERIVED if any(_expr_level(x, names) != NONE for x in xs) else NONE

    if isinstance(e, Identifier):
        return names.get(e.name, NONE)
    if isinstance(e, BinaryExpr):
        return any_(e.left, e.right) if e.op in PROPAGATE else NONE
    if isinstance(e, UnaryExpr):
        return any_(e.operand) if e.op in PROPAGATE_UNARY else NONE
    if isinstance(e, TernaryExpr):
        return any_(e.consequent, e.alternate)
    if isinstance(e, CallExpr):
        # A builtin (identifier callee); a helper's return is not followed.
        return any_(*e.args) if isinstance(e.callee, Identifier) else NONE
    return NONE


def _collect_locktime_locals(body, params: dict[str, int]) -> dict[str, int]:
    """Taint of the method's locals and parameters, from every binding in the
    body (declaration or assignment, anywhere) plus one binding per tainted
    parameter. Order-blind on purpose, as the ANF names every binding the same."""
    binds: list = [(n, lv) for n, lv in params.items()]

    def visit(stmts) -> None:
        for st in stmts or []:
            if isinstance(st, VariableDeclStmt):
                binds.append((st.name, st.init))
            elif isinstance(st, AssignmentStmt) and isinstance(st.target, Identifier):
                binds.append((st.target.name, st.value))
            elif isinstance(st, IfStmt):
                visit(st.then)
                if st.else_:
                    visit(st.else_)
            elif isinstance(st, ForStmt):
                if st.init is not None:
                    visit([st.init])
                visit(st.body)

    visit(body)

    def tainted(b, t) -> bool:
        if isinstance(b, int):
            return b != NONE
        return _expr_level(b, {n: DIRECT for n in t}) != NONE

    def direct(b, d) -> bool:
        if isinstance(b, int):
            return b == DIRECT
        return _is_read(b) or (isinstance(b, Identifier) and b.name in d)

    return solve_taint(binds, tainted, direct)


class _SourceGates:
    def __init__(self, contract) -> None:
        self.privates = {m.name: m for m in contract.methods if m.visibility == "private"}
        # Helper exits, by helper name and the taint level of each parameter.
        self.helper_exits: dict[tuple, frozenset[int]] = {}
        self.in_progress: set[str] = set()
        self.locals: dict[str, int] = {}

    def exits(self, method, params: dict[str, int]) -> frozenset[int]:
        saved = self.locals
        self.locals = _collect_locktime_locals(method.body, params)
        live, returned = self._stmts(method.body, FRESH)
        self.locals = saved
        return live | returned

    def _level(self, e) -> int:
        return _expr_level(e, self.locals)

    def _compare(self, e) -> str:
        if not isinstance(e, BinaryExpr):
            return "none"
        return classify_compare(
            e.op, e.left, e.right, self._level,
            lambda x: x.value if isinstance(x, BigIntLiteral) else None,
        )

    def _asserted_pin(self, e) -> bool:
        if self._compare(e) == "pin":
            return True
        if isinstance(e, BinaryExpr) and e.op == "&&":
            return self._asserted_pin(e.left) or self._asserted_pin(e.right)
        return False

    def _stmts(self, stmts, states):
        live = states
        returned: frozenset[int] = frozenset()
        for st in stmts or []:
            if not live:
                break
            live, r = self._stmt(st, live)
            returned = returned | r
        return live, returned

    def _stmt(self, st, states):
        none: frozenset[int] = frozenset()
        if isinstance(st, AssignmentStmt):
            return self._expr(st.value, self._expr(st.target, states)), none
        if isinstance(st, ExpressionStmt):
            return self._expr(st.expr, states), none
        if isinstance(st, VariableDeclStmt):
            return self._expr(st.init, states), none
        if isinstance(st, ReturnStmt):
            return none, (self._expr(st.value, states) if st.value is not None else states)
        if isinstance(st, IfStmt):
            c = self._expr(st.condition, states)
            tl, tr = self._stmts(st.then, c)
            el, er = self._stmts(st.else_, c) if st.else_ else (c, none)
            return tl | el, tr | er
        if isinstance(st, ForStmt):
            il, ir = self._stmt(st.init, states) if st.init is not None else (states, none)
            c = self._expr(st.condition, il)
            bl, br = self._stmts(st.body, c)
            ul, ur = self._stmt(st.update, bl) if st.update is not None else (bl, none)
            return c | ul, ir | br | ur
        return states, none

    def _expr(self, e, states):
        if e is None:
            return states
        if isinstance(e, CallExpr):
            s = states
            if not isinstance(e.callee, Identifier):
                s = self._expr(e.callee, s)
            for a in e.args:
                s = self._expr(a, s)
            if _is_call_to(e, "assert") and e.args and self._asserted_pin(e.args[0]):
                return or_all(s, P)
            callee = e.callee
            name = callee.property if isinstance(callee, (PropertyAccessExpr, MemberExpr)) else None
            helper = self.privates.get(name) if name is not None else None
            if helper is not None:
                return compose(s, self._helper(helper, [self._level(a) for a in e.args]))
            return s
        if isinstance(e, BinaryExpr):
            s = self._expr(e.right, self._expr(e.left, states))
            return or_all(s, G) if self._compare(e) == "gate" else s
        if isinstance(e, (UnaryExpr, IncrementExpr, DecrementExpr)):
            return self._expr(e.operand, states)
        if isinstance(e, TernaryExpr):
            c = self._expr(e.condition, states)
            return self._expr(e.consequent, c) | self._expr(e.alternate, c)
        if isinstance(e, IndexAccessExpr):
            return self._expr(e.index, self._expr(e.object, states))
        if isinstance(e, MemberExpr):
            return self._expr(e.object, states)
        if isinstance(e, ArrayLiteralExpr):
            s = states
            for el in e.elements:
                s = self._expr(el, s)
            return s
        return states

    def _helper(self, m, arg_levels) -> frozenset[int]:
        params, sig = helper_params(m.params, arg_levels)
        key = (m.name, sig)
        cached = self.helper_exits.get(key)
        if cached is not None:
            return cached
        # Recursion is refused by the validator; a cycle contributes nothing.
        if m.name in self.in_progress:
            return FRESH
        self.in_progress.add(m.name)
        ex = self.exits(m, params)
        self.in_progress.discard(m.name)
        self.helper_exits[key] = ex
        return ex
