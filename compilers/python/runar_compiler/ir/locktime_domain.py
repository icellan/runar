"""D26 on the --ir path.

``--ir`` skips typecheck, where the source path refuses a lower-bound locktime
gate with no asserted domain pin on its path. Re-derived from the ANF of every
public method (stateless and stateful): a ``bin_op`` gate whose operand
resolves (through ``load_const "@ref:"`` aliases) to a ``call
extractLocktime``, and an ``assert`` whose value resolves to a pin compare, or
to the ``&&`` lowering (a value ``if`` whose ``else`` arm is the constant
``false``) of a chain with a pin conjunct. Mirrors ``assertIrLocktimeDomain``
in packages/runar-compiler/src/passes/locktime-domain.ts; run right after the
D15 preimage rules.
"""

from __future__ import annotations

from runar_compiler.frontend.locktime_domain import (
    DIRECT,
    FRESH,
    G,
    NONE,
    P,
    PROPAGATE,
    PROPAGATE_UNARY,
    classify_compare,
    compose,
    helper_params,
    locktime_domain_message,
    or_all,
    solve_taint,
    unpinned,
)
from runar_compiler.ir.preimage_rules import _ref_target
from runar_compiler.ir.types import ANFMethod, ANFProgram, ANFValue


def _reads(bindings) -> bool:
    for b in bindings or []:
        v = b.value
        if v.kind == "call" and v.func == "extractLocktime":
            return True
        if v.kind == "if" and (_reads(v.then) or _reads(v.else_)):
            return True
        if v.kind == "loop" and _reads(v.body):
            return True
    return False


def locktime_domain_error(program: ANFProgram) -> str | None:
    """The D26 text for the first public method with an unpinned gate."""
    # Prefilter (as contract_reads_locktime): no extractLocktime call, no gate.
    if not any(_reads(m.body) for m in program.methods):
        return None
    privates = {
        m.name: m for m in program.methods if not m.is_public and m.name != "constructor"
    }
    exits_of: dict[tuple, frozenset[int]] = {}
    in_progress: set[str] = set()

    def exits(m: ANFMethod, arg_levels) -> frozenset[int]:
        params, sig = helper_params(m.params, arg_levels)
        key = (m.name, sig)
        cached = exits_of.get(key)
        if cached is not None:
            return cached
        if m.name in in_progress:
            return FRESH
        in_progress.add(m.name)

        def helper(name: str, levels):
            t = privates.get(name)
            return exits(t, levels) if t is not None else None

        ex = _IrGates(m, params, helper).run(m.body, FRESH)
        in_progress.discard(m.name)
        exits_of[key] = ex
        return ex

    for m in program.methods:
        if not m.is_public or m.name == "constructor":
            continue
        if unpinned(exits(m, [])):
            return locktime_domain_message(m.name)
    return None


def _is_const_false_arm(arm) -> bool:
    if not arm or len(arm) != 1:
        return False
    v = arm[0].value
    return v.kind == "load_const" and v.const_bool is False


class _IrGates:
    def __init__(self, method: ANFMethod, params: dict[str, int], helper_exits) -> None:
        self.helper_exits = helper_exits
        # Every binding of the method, by name (a name bound more than once
        # keeps all its values).
        self.defs: dict[str, list[ANFValue]] = {}

        def index(bs) -> None:
            for b in bs or []:
                self.defs.setdefault(b.name, []).append(b.value)
                v = b.value
                if v.kind == "if":
                    index(v.then)
                    index(v.else_)
                elif v.kind == "loop":
                    index(v.body)

        index(method.body)
        binds = [(n, v) for n, vs in self.defs.items() for v in vs]

        def last(arm):
            return arm[-1].name if arm else None

        def tainted(v: ANFValue, t) -> bool:
            r = _ref_target(v)
            if r is not None:
                return r in t
            if v.kind == "call":
                return v.func == "extractLocktime" or any(a in t for a in v.args or [])
            if v.kind == "load_param":
                return params.get(v.name, NONE) != NONE
            if v.kind == "bin_op":
                return v.op in PROPAGATE and (v.left in t or v.right in t)
            if v.kind == "unary_op":
                return v.op in PROPAGATE_UNARY and v.operand in t
            if v.kind == "if":
                return any(n is not None and n in t for n in (last(v.then), last(v.else_)))
            return False

        def direct(v: ANFValue, d) -> bool:
            r = _ref_target(v)
            if r is not None:
                return r in d
            if v.kind == "call":
                return v.func == "extractLocktime"
            if v.kind == "load_param":
                return params.get(v.name) == DIRECT
            return False

        self.taint = solve_taint(binds, tainted, direct)

    def _level(self, name) -> int:
        return self.taint.get(name, NONE)

    def _literal(self, name, seen=None) -> int | None:
        seen = set() if seen is None else seen
        if name in seen:
            return None
        seen.add(name)
        vs = self.defs.get(name) or []
        if len(vs) != 1:
            return None
        v = vs[0]
        if v.kind != "load_const":
            return None
        if v.const_big_int is not None and v.const_bool is None:
            return v.const_big_int
        r = _ref_target(v)
        return self._literal(r, seen) if r is not None else None

    def _compare(self, v: ANFValue) -> str:
        if v.kind != "bin_op":
            return "none"
        return classify_compare(v.op, v.left, v.right, self._level, self._literal)

    def _asserted_pin(self, name, seen=None) -> bool:
        """Does ``assert(name)`` imply a pin?"""
        seen = set() if seen is None else seen
        if name is None or name in seen:
            return False
        seen.add(name)
        vs = self.defs.get(name) or []
        if len(vs) != 1:
            return False
        v = vs[0]
        if self._compare(v) == "pin":
            return True
        r = _ref_target(v)
        if r is not None:
            return self._asserted_pin(r, seen)
        # ``a && b`` lowers to ``if a then [..., b] else [false]``.
        if v.kind == "if" and _is_const_false_arm(v.else_) and v.then:
            return self._asserted_pin(v.cond, seen) or self._asserted_pin(v.then[-1].name, seen)
        return False

    def run(self, bs, states: frozenset[int]) -> frozenset[int]:
        s = states
        for b in bs or []:
            v = b.value
            if v.kind == "bin_op":
                if self._compare(v) == "gate":
                    s = or_all(s, G)
            elif v.kind == "assert":
                if self._asserted_pin(v.value_ref):
                    s = or_all(s, P)
            elif v.kind == "method_call":
                ex = self.helper_exits(v.method, [self._level(a) for a in v.args or []])
                if ex is not None:
                    s = compose(s, ex)
            elif v.kind == "if":
                s = self.run(v.then, s) | self.run(v.else_, s)
            elif v.kind == "loop":
                s = s | self.run(v.body, s)
        return s
