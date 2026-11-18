"""Two rules about where a StatefulSmartContract's satoshis can go, both read
off the side-effect summary, so they see exactly the effects the continuation
is injected from. Mirrors packages/runar-compiler/src/passes/continuation-rules.ts
(same texts in all seven tiers).

#199 (warning, validator): no public method is terminal and none sizes its own
outputs (addOutput / addRawOutput, directly or via a private helper), so every
spend takes the default continuation whose F-024 floor never lets the value
shrink: the satoshis can never leave.

D18 (error, typecheck; re-derived on the ANF for --ir in
ir/continuation_rules.py), PER PATH: any addOutput / addRawOutput anywhere in a
public method (directly or in a private helper, on any branch) removes the
auto-injected continuation for the whole method, and only addOutput carries
state, so a path that writes state and reaches no addOutput drops its write and
the contract's value leaves with the spend. A path that writes nothing is
terminal by design and is accepted.
"""

from __future__ import annotations

from runar_compiler.frontend.ast_nodes import (
    ArrayLiteralExpr,
    AssignmentStmt,
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
from runar_compiler.frontend.side_effect_summary import (
    MethodEffects,
    continuation_shape_for,
)


def release_trap_message(contract: str) -> str:
    return (
        f"contract '{contract}' has no terminal method and no public method that calls "
        f"addOutput/addRawOutput; its satoshis can never leave instances of '{contract}'"
    )


def dropped_continuation_message(method: str) -> str:
    return (
        f"method '{method}' writes contract state on a path that reaches no addOutput(): a method "
        "that declares its own outputs (addOutput/addRawOutput) gets no auto-injected continuation, "
        "so on that path the state write would be lost and the contract's satoshis would leave with "
        "the spend. Add this.addOutput(satoshis, ...) on every path that writes state, or stop "
        "writing state on a path meant to end the contract"
    )


# Path-state bits: state written / addOutput reached. A set of these (at most
# four) flows through a method body.
PATH_W = 1
PATH_A = 2


def or_all(states: frozenset[int], bits: int) -> frozenset[int]:
    return frozenset(x | bits for x in states)


def compose(states: frozenset[int], exits: frozenset[int]) -> frozenset[int]:
    return frozenset(x | y for x in states for y in exits)


def paths_dropped(states) -> bool:
    """Some path wrote state and reached no addOutput."""
    return any(x & PATH_W and not x & PATH_A for x in states)


_FRESH = frozenset({0})
_NONE: frozenset[int] = frozenset()


def drops_continuation(contract, method, effects: MethodEffects) -> bool:
    """D18 (source path), per path: the method declares a state output
    somewhere (so it gets no auto-continuation) and some path through it writes
    state without reaching an addOutput. Mirrors dropsContinuation /
    SourcePaths in continuation-rules.ts."""
    if not effects.has_state_output:
        return False
    return paths_dropped(_SourcePaths(contract).exits(method.body))


def _callee_name(callee) -> tuple[str | None, bool]:
    """The callee's name and whether it is a member form (this.x / a.x)."""
    if isinstance(callee, (PropertyAccessExpr, MemberExpr)):
        return callee.property, True
    if isinstance(callee, Identifier):
        return callee.name, False
    return None, False


class _SourcePaths:
    def __init__(self, contract) -> None:
        self.mutable = {p.name for p in contract.properties if not p.readonly}
        self.privates = {m.name: m for m in contract.methods if m.visibility != "public"}
        self.helper_exits: dict[str, frozenset[int]] = {}
        self._precompute_helpers()

    def _precompute_helpers(self) -> None:
        """N-264: computing a helper's exits by recursing from the caller's
        walk (as the TS reference does) needs D*K frames for a chain of D
        helpers each calling the next under K nested ifs. Instead every
        helper's exits are computed callees-first, in an iterative post-order
        over the private call graph, so one body walk only recurses as deep as
        that body's own nesting. Memoized results are order-independent on an
        acyclic graph, so this is exactly the TS result; a cycle (refused by
        the validator) contributes {0}, as in TS."""
        done: set[str] = set()
        on_stack: set[str] = set()
        for root in self.privates.values():
            if root.name in done:
                continue
            work = [(root, self._direct_callees(root.body), 0)]
            on_stack.add(root.name)
            while work:
                cur, callees, idx = work[-1]
                if idx < len(callees):
                    work[-1] = (cur, callees, idx + 1)
                    nxt = callees[idx]
                    if nxt in done or nxt in on_stack:
                        continue
                    target = self.privates[nxt]
                    on_stack.add(nxt)
                    work.append((target, self._direct_callees(target.body), 0))
                    continue
                self.helper_exits[cur.name] = self.exits(cur.body)
                on_stack.discard(cur.name)
                done.add(cur.name)
                work.pop()

    def _direct_callees(self, body) -> list[str]:
        out: list[str] = []

        def stmt(st) -> None:
            if isinstance(st, AssignmentStmt):
                expr(st.target)
                expr(st.value)
            elif isinstance(st, ExpressionStmt):
                expr(st.expr)
            elif isinstance(st, VariableDeclStmt):
                expr(st.init)
            elif isinstance(st, ReturnStmt):
                expr(st.value)
            elif isinstance(st, IfStmt):
                expr(st.condition)
                for x in st.then or []:
                    stmt(x)
                for x in st.else_ or []:
                    stmt(x)
            elif isinstance(st, ForStmt):
                if st.init is not None:
                    stmt(st.init)
                expr(st.condition)
                for x in st.body or []:
                    stmt(x)
                if st.update is not None:
                    stmt(st.update)

        def expr(e) -> None:
            if e is None:
                return
            if isinstance(e, (IncrementExpr, DecrementExpr, UnaryExpr)):
                expr(e.operand)
            elif isinstance(e, CallExpr):
                if not isinstance(e.callee, Identifier):
                    expr(e.callee)
                for a in e.args:
                    expr(a)
                name, _ = _callee_name(e.callee)
                if name is not None and name in self.privates and name not in out:
                    out.append(name)
            elif isinstance(e, BinaryExpr):
                expr(e.left)
                expr(e.right)
            elif isinstance(e, TernaryExpr):
                expr(e.condition)
                expr(e.consequent)
                expr(e.alternate)
            elif isinstance(e, IndexAccessExpr):
                expr(e.object)
                expr(e.index)
            elif isinstance(e, MemberExpr):
                expr(e.object)
            elif isinstance(e, ArrayLiteralExpr):
                for el in e.elements:
                    expr(el)

        for st in body or []:
            stmt(st)
        return out

    def exits(self, body) -> frozenset[int]:
        """Exit states (fallthrough and return) of a body entered with a fresh path."""
        live, returned = self._stmts(body, _FRESH)
        return live | returned

    def _stmts(self, stmts, states):
        live = states
        returned: frozenset[int] = _NONE
        for st in stmts or []:
            if not live:
                break
            live, r = self._stmt(st, live)
            returned = returned | r
        return live, returned

    def _stmt(self, st, states):
        if isinstance(st, AssignmentStmt):
            s = self._expr(st.target, states)
            s = self._expr(st.value, s)
            if self._writes_mutable(st.target):
                s = or_all(s, PATH_W)
            return s, _NONE
        if isinstance(st, ExpressionStmt):
            return self._expr(st.expr, states), _NONE
        if isinstance(st, VariableDeclStmt):
            return self._expr(st.init, states), _NONE
        if isinstance(st, ReturnStmt):
            return _NONE, (self._expr(st.value, states) if st.value is not None else states)
        if isinstance(st, IfStmt):
            c = self._expr(st.condition, states)
            tl, tr = self._stmts(st.then, c)
            el, er = self._stmts(st.else_, c) if st.else_ else (c, _NONE)
            return tl | el, tr | er
        if isinstance(st, ForStmt):
            il, ir = self._stmt(st.init, states) if st.init is not None else (states, _NONE)
            c = self._expr(st.condition, il)
            bl, br = self._stmts(st.body, c)
            ul, ur = self._stmt(st.update, bl) if st.update is not None else (bl, _NONE)
            return c | ul, ir | br | ur
        return states, _NONE

    def _writes_mutable(self, target) -> bool:
        t = target
        while isinstance(t, IndexAccessExpr):
            t = t.object
        return isinstance(t, PropertyAccessExpr) and t.property in self.mutable

    def _expr(self, e, states):
        """Every call in e runs, in evaluation order."""
        if e is None:
            return states
        if isinstance(e, (IncrementExpr, DecrementExpr)):
            s = self._expr(e.operand, states)
            return or_all(s, PATH_W) if self._writes_mutable(e.operand) else s
        if isinstance(e, CallExpr):
            s = states
            if not isinstance(e.callee, Identifier):
                s = self._expr(e.callee, s)
            for a in e.args:
                s = self._expr(a, s)
            name, member = _callee_name(e.callee)
            if member and name == "addOutput":
                return or_all(s, PATH_A)
            if name is not None and name in self.privates:
                # A helper not yet computed is on a cycle: {0}.
                return compose(s, self.helper_exits.get(name, _FRESH))
            return s
        if isinstance(e, BinaryExpr):
            return self._expr(e.right, self._expr(e.left, states))
        if isinstance(e, UnaryExpr):
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


def release_trap_warning(contract, summary: dict[str, MethodEffects]) -> str | None:
    """The #199 warning text when it applies (stateful contracts only)."""
    if contract.parent_class != "StatefulSmartContract":
        return None
    publics = [m for m in contract.methods if m.visibility == "public"]
    if not publics:
        return None
    for m in publics:
        eff = summary.get(m.name)
        if eff is None or continuation_shape_for(eff).is_terminal or eff.has_state_output:
            return None
    return release_trap_message(contract.name)
