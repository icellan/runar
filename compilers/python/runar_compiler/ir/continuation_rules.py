"""D18 on the --ir path.

``--ir`` skips typecheck, where the source path refuses a public stateful
method that writes state and declares raw outputs but no ``addOutput`` (its
state write would be dropped and the contract's satoshis would leave with the
spend). Re-derived from the ANF: ``update_prop`` = state write,
``add_output`` / ``add_raw_output`` = declared outputs, at any depth (if
then/else, loop body) and through ``method_call`` to private methods. Mirrors
``assertIrNoDroppedContinuation`` in
packages/runar-compiler/src/passes/continuation-rules.ts. Run for
StatefulSmartContract programs after the N-101 scaffolding check.
"""

from __future__ import annotations

from runar_compiler.frontend.continuation_rules import dropped_continuation_message
from runar_compiler.ir.types import ANFBinding, ANFMethod, ANFProgram


def dropped_continuation_error(program: ANFProgram) -> str | None:
    privates = {
        m.name: m for m in program.methods if not m.is_public and m.name != "constructor"
    }
    for m in program.methods:
        if m.is_public and m.name != "constructor" and _drops(m, privates):
            return dropped_continuation_message(m.name)
    return None


def _drops(method: ANFMethod, privates: dict[str, ANFMethod]) -> bool:
    seen = {"writes": False, "raw": False, "add": False}
    visited: set[str] = set()

    def walk(bindings: list[ANFBinding] | None) -> None:
        for b in bindings or []:
            v = b.value
            if v.kind == "update_prop":
                seen["writes"] = True
            elif v.kind == "add_raw_output":
                seen["raw"] = True
            elif v.kind == "add_output":
                seen["add"] = True
            elif v.kind == "method_call":
                target = privates.get(v.method or "")
                if target is not None and target.name not in visited:
                    visited.add(target.name)
                    walk(target.body)
            walk(v.then)
            walk(v.else_)
            walk(v.body)

    walk(method.body)
    return seen["writes"] and seen["raw"] and not seen["add"]
