"""Two rules about where a StatefulSmartContract's satoshis can go, both read
off the side-effect summary, so they see exactly the effects the continuation
is injected from. Mirrors packages/runar-compiler/src/passes/continuation-rules.ts
(same texts in all seven tiers).

#199 (warning, validator): no public method is terminal and none sizes its own
outputs (addOutput / addRawOutput, directly or via a private helper), so every
spend takes the default continuation whose F-024 floor never lets the value
shrink: the satoshis can never leave.

D18 (error, typecheck; re-derived on the ANF for --ir in
ir/continuation_rules.py): a public method that writes state and calls
addRawOutput but never addOutput gets no auto-injected continuation, so the
state write is dropped and the contract's value leaves with the spend.
"""

from __future__ import annotations

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
        f"method '{method}' writes contract state but emits no state continuation: it calls "
        "addRawOutput() without addOutput(), and a method that declares its own outputs gets no "
        "auto-injected continuation, so the state write would be lost and the contract's satoshis "
        "would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or "
        "stop writing state in a method meant to end the contract"
    )


def drops_continuation(effects: MethodEffects) -> bool:
    return effects.mutates_state and effects.has_state_output and not effects.calls_add_output


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
