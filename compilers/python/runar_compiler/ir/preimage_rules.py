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


class _View:
    def __init__(self, m: ANFMethod, implicit_tx: bool) -> None:
        self.defs: dict[str, ANFValue] = {}
        self.dup: set[str] = set()

        def collect(bs: list[ANFBinding] | None) -> None:
            for b in bs or []:
                if b.name in self.defs:
                    self.dup.add(b.name)
                self.defs[b.name] = b.value
                if b.value.kind == "if":
                    collect(b.value.then)
                    collect(b.value.else_)
                elif b.value.kind == "loop":
                    collect(b.value.body)

        collect(m.body)
        self.shp = {p.name for p in m.params if p.type == _SHP}
        own = any(p.name == "txPreimage" for p in m.params)
        self.implicit = (not m.is_public) and implicit_tx and not own

    def resolve(self, name: str | None) -> str | None:
        seen: set[str] = set()
        while name is not None and name not in self.dup and name not in seen:
            seen.add(name)
            v = self.defs.get(name)
            if v is None:
                return None
            if v.kind == "load_param":
                if v.name in self.shp:
                    return v.name
                return v.name if self.implicit and v.name == "txPreimage" else None
            if v.kind == "load_prop":
                return v.name if self.implicit and v.name == "txPreimage" else None
            name = _ref_target(v)
        return None

    def truth_checks(self, name: str | None, seen: set[str]):
        if name is None or name in self.dup or name in seen:
            return set()
        seen.add(name)
        v = self.defs.get(name)
        if v is None:
            return set()
        if v.kind == "check_preimage":
            o = self.resolve(v.preimage)
            return {o} if o is not None else set()
        if v.kind == "load_const":
            if v.const_bool is False:
                return _ALL
            nxt = _ref_target(v)
            return self.truth_checks(nxt, seen) if nxt is not None else set()
        if v.kind == "if" and not v.results:
            if not v.then or not v.else_:
                return set()
            t = _union(self.truth_checks(v.cond, seen), self.truth_checks(v.then[-1].name, seen))
            return _intersect(t, self.truth_checks(v.else_[-1].name, seen))
        return set()


def preimage_rule_errors(program: ANFProgram) -> list[str]:
    errors = [preimage_property_message(p.name) for p in program.properties if p.type == _SHP]
    methods = {m.name: m for m in program.methods}
    publics = [m for m in program.methods if m.is_public and m.name != "constructor"]
    implicit_tx = (
        bool(publics)
        and all(any(p.name == "txPreimage" and p.type == _SHP for p in m.params) for m in publics)
        and not any(p.name == "txPreimage" for p in program.properties)
    )
    memo: dict[str, set[str]] = {}

    def must_checked(m: ANFMethod, stack: frozenset[str]) -> set[str]:
        if m.name in memo:
            return memo[m.name]
        if m.name in stack:
            return set()
        mv = _View(m, implicit_tx)
        inner = stack | {m.name}

        def walk(bs: list[ANFBinding] | None, done_in: set[str]) -> set[str]:
            done = set(done_in)
            for b in bs or []:
                v = b.value
                if v.kind == "assert":
                    c = mv.truth_checks(v.value_ref, set())
                    if c is not None:
                        done |= c
                elif v.kind == "if":
                    done = walk(v.then, done) & walk(v.else_, done)
                elif v.kind == "method_call":
                    target = methods.get(v.method or "")
                    if target is not None and not target.is_public:
                        checked = must_checked(target, inner)
                        args = v.args or []
                        for i, p in enumerate(target.params):
                            if p.name in checked and i < len(args):
                                o = mv.resolve(args[i])
                                if o is not None:
                                    done.add(o)
            return done

        result = walk(m.body, set())
        memo[m.name] = result
        return result

    for m in program.methods:
        if m.name == "constructor":
            continue
        mv = _View(m, implicit_tx)

        def visit(bs: list[ANFBinding] | None) -> None:
            for b in bs or []:
                v = b.value
                args = v.args or []
                if v.kind == "call" and v.func in PREIMAGE_EXTRACTORS:
                    if mv.resolve(args[0] if args else None) is None:
                        errors.append(unchecked_preimage_arg_message(v.func))
                elif v.kind == "method_call":
                    target = methods.get(v.method or "")
                    if target is not None and not target.is_public and any(
                        p.type == _SHP and mv.resolve(args[i] if i < len(args) else None) is None
                        for i, p in enumerate(target.params)
                    ):
                        errors.append(unchecked_preimage_arg_message(target.name))
                elif v.kind == "if":
                    visit(v.then)
                    visit(v.else_)
                elif v.kind == "loop":
                    visit(v.body)

        visit(m.body)
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
