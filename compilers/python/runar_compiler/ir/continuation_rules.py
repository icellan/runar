"""D18 on the --ir path.

``--ir`` skips typecheck, where the source path refuses a public stateful
method that declares its own outputs and has a path that writes state but
reaches no ``addOutput`` (that write would be dropped and the contract's
satoshis would leave with the spend). Re-derived from the ANF, per path,
through ``if`` arms, loop bodies and ``method_call``s to private methods. Mirrors
``assertIrNoDroppedContinuation`` in
packages/runar-compiler/src/passes/continuation-rules.ts. Run for
StatefulSmartContract programs after the N-101 scaffolding check.

D27 rides the same walk: a path whose last ``add_output`` is followed by an
``update_prop`` is refused with D18's sibling text (D18 wins in a method that
has both).
"""

from __future__ import annotations

from runar_compiler.frontend.continuation_rules import (
    add_output,
    compose,
    dead_state_write_message,
    dropped_continuation_message,
    verdict,
    write,
)
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram


def dropped_continuation_error(program: ANFProgram) -> str | None:
    privates = {
        m.name: m for m in program.methods if not m.is_public and m.name != "constructor"
    }
    for m in program.methods:
        if not m.is_public or m.name == "constructor":
            continue
        v = _verdict(m, privates)
        if v == "dropped":
            return dropped_continuation_message(m.name)
        if v == "dead-write":
            return dead_state_write_message(m.name)
    return None


def _verdict(method: ANFMethod, privates: dict[str, ANFMethod]) -> str | None:
    """The per-path rule on ANF: update_prop = state write, add_output =
    addOutput, add_raw_output / add_output = a declared output (suppresses the
    auto-continuation). ``if`` unions its arms, a loop body unions with
    skipping it, a method_call to a private method composes with that method's
    exits."""

    def declares(bindings, seen: set[str]) -> bool:
        for b in bindings or []:
            v = b.value
            if v.kind in ("add_output", "add_raw_output"):
                return True
            if v.kind == "method_call":
                t = privates.get(v.method or "")
                if t is not None and t.name not in seen:
                    seen.add(t.name)
                    if declares(t.body, seen):
                        return True
            if any(isinstance(x, list) and declares(x, seen) for x in (v.then, v.else_, v.body)):
                return True
        return False

    if not declares(method.body, set()):
        return None

    exits_of: dict[str, frozenset[int]] = {}
    in_progress: set[str] = set()

    def run(bindings, states: frozenset[int]) -> frozenset[int]:
        s = states
        for b in bindings or []:
            v = b.value
            if v.kind == "update_prop":
                s = write(s)
            elif v.kind == "add_output":
                s = add_output(s)
            elif v.kind == "method_call":
                t = privates.get(v.method or "")
                if t is not None:
                    ex = exits_of.get(t.name)
                    if ex is None:
                        if t.name in in_progress:
                            ex = frozenset({0})
                        else:
                            in_progress.add(t.name)
                            ex = run(t.body, frozenset({0}))
                            in_progress.discard(t.name)
                            exits_of[t.name] = ex
                    s = compose(s, ex)
            elif isinstance(v.then, list) or isinstance(v.else_, list):
                t_ = run(v.then, s) if isinstance(v.then, list) else s
                e_ = run(v.else_, s) if isinstance(v.else_, list) else s
                s = t_ | e_
            elif isinstance(v.body, list):
                s = s | run(v.body, s)
        return s

    return verdict(run(method.body, frozenset({0})))
