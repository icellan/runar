//! Two rules about where a StatefulSmartContract's satoshis can go, both
//! read off the side-effect summary, so they see exactly the effects the
//! continuation is injected from. Mirrors
//! `packages/runar-compiler/src/passes/continuation-rules.ts` (same texts in
//! all seven tiers).
//!
//! #199 (warning, validator): no public method is terminal and none sizes its
//! own outputs (addOutput / addRawOutput, directly or via a private helper),
//! so every spend takes the default continuation whose F-024 floor never lets
//! the value shrink: the satoshis can never leave.
//!
//! D18 (error, typecheck; re-derived on the ANF for `--ir` in
//! `ir/continuation_rules.rs`): a public method that writes state and calls
//! addRawOutput but never addOutput gets no auto-injected continuation, so
//! the state write is dropped and the contract's value leaves with the spend.

use super::ast::{ContractNode, Visibility};
use super::side_effect_summary::{ContinuationShape, MethodEffects, SideEffectSummary};

/// #199: the shared warning text.
pub fn release_trap_message(contract: &str) -> String {
    format!(
        "contract '{contract}' has no terminal method and no public method that calls \
addOutput/addRawOutput; its satoshis can never leave instances of '{contract}'"
    )
}

/// D18: the shared error text.
pub fn dropped_continuation_message(method: &str) -> String {
    format!(
        "method '{method}' writes contract state but emits no state continuation: it calls \
addRawOutput() without addOutput(), and a method that declares its own outputs gets no \
auto-injected continuation, so the state write would be lost and the contract's satoshis \
would leave with the spend. Add this.addOutput(satoshis, ...) to carry the new state, or \
stop writing state in a method meant to end the contract"
    )
}

/// D18: the method writes state and only raw outputs replace its continuation.
pub fn drops_continuation(effects: &MethodEffects) -> bool {
    effects.mutates_state && effects.has_state_output && !effects.calls_add_output
}

/// #199: the contract-level warning text, when it applies.
pub fn release_trap_warning(contract: &ContractNode, summary: &SideEffectSummary) -> Option<String> {
    if contract.parent_class != "StatefulSmartContract" {
        return None;
    }
    let mut publics = contract.methods.iter().filter(|m| m.visibility == Visibility::Public).peekable();
    publics.peek()?;
    let trapped = publics.all(|m| match summary.get(&m.name) {
        Some(eff) => !ContinuationShape::for_effects(eff).is_terminal && !eff.has_state_output,
        None => false,
    });
    trapped.then(|| release_trap_message(&contract.name))
}
