"""D15: the preimage rules on ``--ir`` input.

Port of packages/runar-compiler/src/passes/ir-preimage-rules.ts (see its header
for the full rule and for what ANF cannot carry). ``--ir`` skips the frontend,
so D9 (no SigHashPreimage property), GK-GAP-010 (a public method's
SigHashPreimage parameter is asserted on every path) and D14 (an extractor
reads only a checked preimage) are re-derived here, failing closed.
"""

from __future__ import annotations

from runar_compiler.frontend.typecheck import (
    PREIMAGE_EXTRACTORS,
    preimage_not_checked_message,
    unchecked_preimage_arg_message,
)
from runar_compiler.frontend.validator import preimage_property_message
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram, ANFValue

_SHP = "SigHashPreimage"
_ALL = None  # "everything": what a constant-false arm implies


def _union(a, b):
    return None if a is None or b is None else a | b


def _intersect(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a & b


def _ref_target(v: ANFValue) -> str | None:
    s = v.const_string
    if v.kind == "load_const" and isinstance(s, str) and s.startswith("@ref:"):
        return s[5:]
    return None


_THEN, _ELSE, _BODY = -1, -2, -3


def _visible(def_path: tuple[int, ...], from_path: tuple[int, ...]) -> bool:
    """Is the binding at ``def_path`` in scope at ``from_path``? Only if it sits
    earlier in the same list or in a list enclosing it: stack lowering resolves
    names by position, so a binding after (or beside) a use never answers for
    it."""
    n = len(def_path)
    if len(from_path) < n or def_path[: n - 1] != from_path[: n - 1]:
        return False
    return def_path[n - 1] < from_path[n - 1]


class _View:
    def __init__(self, m: ANFMethod, implicit_tx: bool) -> None:
        self.defs: dict[str, tuple[ANFValue, tuple[int, ...]]] = {}
        # A name bound more than once, or under a parameter's name (the
        # parameter slot answers to it too), never resolves.
        self.poisoned: set[str] = {p.name for p in m.params}

        def collect(bs: list[ANFBinding] | None, at: tuple[int, ...]) -> None:
            for i, b in enumerate(bs or []):
                path = at + (i,)
                if b.name in self.defs:
                    self.poisoned.add(b.name)
                self.defs[b.name] = (b.value, path)
                if b.value.kind == "if":
                    collect(b.value.then, path + (_THEN,))
                    collect(b.value.else_, path + (_ELSE,))
                elif b.value.kind == "loop":
                    collect(b.value.body, path + (_BODY,))

        collect(m.body, ())
        self.shp = {p.name for p in m.params if p.type == _SHP}
        own = any(p.name == "txPreimage" for p in m.params)
        self.implicit = (not m.is_public) and implicit_tx and not own

    def lookup(self, name: str | None, from_path: tuple[int, ...]):
        if name is None or name in self.poisoned:
            return None
        d = self.defs.get(name)
        return d if d is not None and _visible(d[1], from_path) else None

    def resolve(self, name: str | None, from_path: tuple[int, ...]) -> str | None:
        for _ in range(len(self.defs) + 1):
            d = self.lookup(name, from_path)
            if d is None:
                return None
            v, path = d
            if v.kind == "load_param":
                if v.name in self.shp:
                    return v.name
                return v.name if self.implicit and v.name == "txPreimage" else None
            if v.kind == "load_prop":
                return v.name if self.implicit and v.name == "txPreimage" else None
            name, from_path = _ref_target(v), path
        return None

    def truth_of(self, name: str | None, from_path: tuple[int, ...], depth: int = 0):
        d = self.lookup(name, from_path)
        return set() if d is None else self.truth_value(d[0], d[1], depth)

    def truth_value(self, v: ANFValue, path: tuple[int, ...], depth: int):
        if depth > len(self.defs):
            return set()
        if v.kind == "check_preimage":
            o = self.resolve(v.preimage, path)
            return {o} if o is not None else set()
        if v.kind == "load_const":
            if v.const_bool is False:
                return _ALL
            nxt = _ref_target(v)
            return self.truth_of(nxt, path, depth + 1) if nxt is not None else set()
        if v.kind == "if" and not v.results:
            if not v.then or not v.else_:
                return set()
            nt, ne = len(v.then) - 1, len(v.else_) - 1
            t = _union(
                self.truth_of(v.cond, path, depth + 1),
                self.truth_value(v.then[nt].value, path + (_THEN, nt), depth + 1),
            )
            return _intersect(t, self.truth_value(v.else_[ne].value, path + (_ELSE, ne), depth + 1))
        return set()


def preimage_rule_errors(program: ANFProgram) -> list[str]:
    errors = [preimage_property_message(p.name) for p in program.properties if p.type == _SHP]
    # A method_call resolves exactly as stack lowering inlines it: to the LAST
    # non-public, non-constructor method of that name (codegen/stack.py). The
    # loader refuses duplicate names first; this never relies on that alone.
    privates = {m.name: m for m in program.methods if not m.is_public and m.name != "constructor"}
    publics = [m for m in program.methods if m.is_public and m.name != "constructor"]
    implicit_tx = (
        bool(publics)
        and all(any(p.name == "txPreimage" and p.type == _SHP for p in m.params) for m in publics)
        and not any(p.name == "txPreimage" for p in program.properties)
    )
    memo: dict[int, set[str]] = {}  # keyed by method identity, never by name

    def must_checked(m: ANFMethod, stack: frozenset[int]) -> set[str]:
        if id(m) in memo:
            return memo[id(m)]
        if id(m) in stack:
            return set()
        mv = _View(m, implicit_tx)
        inner = stack | {id(m)}

        def walk(bs: list[ANFBinding] | None, at: tuple[int, ...], done_in: set[str]) -> set[str]:
            done = set(done_in)
            for i, b in enumerate(bs or []):
                path = at + (i,)
                v = b.value
                if v.kind == "assert":
                    c = mv.truth_of(v.value_ref, path)
                    if c is not None:
                        done |= c
                elif v.kind == "if":
                    done = walk(v.then, path + (_THEN,), done) & walk(v.else_, path + (_ELSE,), done)
                elif v.kind == "method_call":
                    target = privates.get(v.method or "")
                    if target is not None:
                        checked = must_checked(target, inner)
                        args = v.args or []
                        for k, p in enumerate(target.params):
                            if p.name in checked and k < len(args):
                                o = mv.resolve(args[k], path)
                                if o is not None:
                                    done.add(o)
            return done

        result = walk(m.body, (), set())
        memo[id(m)] = result
        return result

    for m in program.methods:
        if m.name == "constructor":
            continue
        mv = _View(m, implicit_tx)

        def visit(bs: list[ANFBinding] | None, at: tuple[int, ...]) -> None:
            for j, b in enumerate(bs or []):
                path = at + (j,)
                v = b.value
                args = v.args or []
                if v.kind == "call" and v.func in PREIMAGE_EXTRACTORS:
                    if mv.resolve(args[0] if args else None, path) is None:
                        errors.append(unchecked_preimage_arg_message(v.func))
                elif v.kind == "method_call":
                    target = privates.get(v.method or "")
                    if target is not None and any(
                        p.type == _SHP and mv.resolve(args[i] if i < len(args) else None, path) is None
                        for i, p in enumerate(target.params)
                    ):
                        errors.append(unchecked_preimage_arg_message(target.name))
                elif v.kind == "if":
                    visit(v.then, path + (_THEN,))
                    visit(v.else_, path + (_ELSE,))
                elif v.kind == "loop":
                    visit(v.body, path + (_BODY,))

        visit(m.body, ())
        if m.is_public:
            done = must_checked(m, frozenset())
            for p in m.params:
                if p.type == _SHP and p.name not in done:
                    errors.append(preimage_not_checked_message(m.name, p.name))
    return errors


def assert_preimage_rules(program: ANFProgram) -> None:
    """Raise the shared diagnostics for every D9 / GK-GAP-010 / D14 violation."""
    errors = preimage_rule_errors(program)
    if errors:
        raise ValueError("IR validation: " + "; ".join(errors))


def assert_unique_method_names(program: ANFProgram) -> None:
    """GK-BUG-015's shared text on the IR path: a repeated method name, refused
    before anything looks a method up by name (the source validator refuses
    it; ``--ir`` did not, so two bodies could share a name)."""
    seen: set[str] = set()
    for m in program.methods:
        if m.name in seen:
            raise ValueError(
                f"IR validation: method '{m.name}' is already declared in this contract and cannot be re-declared"
            )
        seen.add(m.name)
