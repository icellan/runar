//! Dead Code Elimination pass for ANF IR.
//!
//! Removes bindings whose results are never referenced by other bindings,
//! preserving bindings with observable side effects (assert, update_prop,
//! check_preimage, add_output, add_raw_output, add_data_output, call,
//! method_call, raw_script). Iterates to a fixed point so transitively
//! dead bindings are also removed.
//!
//! This module is the canonical, standalone DCE pass for the Rust compiler.
//! It mirrors the Zig reference implementation in
//! `compilers/zig/src/passes/dce.zig`. The earlier inline implementation in
//! `anf_optimize.rs` has been surgically extracted here.
//!
//! Behaviour: byte-for-byte identical to the previous inline DCE in
//! `anf_optimize.rs`. Verified by the conformance suite (cross-tier hex
//! parity) and the optimizer unit tests.

use std::collections::HashSet;

use crate::ir::{ANFMethod, ANFProgram, ANFValue};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Eliminate dead bindings across every method in the program.
/// Returns a new program; the input is consumed.
pub fn eliminate_dead_code(program: ANFProgram) -> ANFProgram {
    let methods: Vec<ANFMethod> = program
        .methods
        .iter()
        .map(eliminate_dead_bindings_method)
        .collect();

    ANFProgram {
        contract_name: program.contract_name,
        parent_class: program.parent_class,
        properties: program.properties,
        methods,
    }
}

/// Eliminate dead (unreferenced, side-effect-free) bindings, iterating to fixed point.
pub fn eliminate_dead_bindings_method(method: &ANFMethod) -> ANFMethod {
    let mut body = method.body.clone();
    loop {
        let mut refs = HashSet::new();
        for binding in &body {
            collect_refs_from_value(&binding.value, &mut refs);
        }

        let before_len = body.len();
        body.retain(|b| refs.contains(&b.name) || has_side_effect(&b.value));

        if body.len() == before_len {
            break;
        }
    }

    ANFMethod {
        name: method.name.clone(),
        params: method.params.clone(),
        body,
        is_public: method.is_public,
    }
}

// ---------------------------------------------------------------------------
// Core algorithm
// ---------------------------------------------------------------------------

/// Collect all referenced binding names from a value.
pub fn collect_refs_from_value(value: &ANFValue, refs: &mut HashSet<String>) {
    match value {
        ANFValue::LoadParam { .. } => {
            // Do NOT track @ref: targets here — matches TS collectRefsFromValue
            // which breaks on load_param without collecting refs.
        }
        ANFValue::LoadProp { .. } | ANFValue::GetStateScript {} => {}
        // raw_script — opaque byte span, no SSA operand refs. Stack effect is
        // declared via in_arity / out_arity.
        ANFValue::RawScript { .. } => {}
        ANFValue::LoadConst { value } => {
            // Track @ref: aliases as references to prevent DCE
            if let serde_json::Value::String(s) = value {
                if let Some(target) = s.strip_prefix("@ref:") {
                    refs.insert(target.to_string());
                }
            }
        }
        ANFValue::BinOp { left, right, .. } => {
            refs.insert(left.clone());
            refs.insert(right.clone());
        }
        ANFValue::UnaryOp { operand, .. } => {
            refs.insert(operand.clone());
        }
        ANFValue::Call { args, .. } => {
            for arg in args {
                refs.insert(arg.clone());
            }
        }
        ANFValue::MethodCall { object, args, .. } => {
            refs.insert(object.clone());
            for arg in args {
                refs.insert(arg.clone());
            }
        }
        ANFValue::If {
            cond,
            then: then_branch,
            else_branch,
        } => {
            refs.insert(cond.clone());
            for b in then_branch {
                collect_refs_from_value(&b.value, refs);
            }
            for b in else_branch {
                collect_refs_from_value(&b.value, refs);
            }
        }
        ANFValue::Loop { body, .. } => {
            for b in body {
                collect_refs_from_value(&b.value, refs);
            }
        }
        ANFValue::Assert { value, .. } => {
            refs.insert(value.clone());
        }
        ANFValue::UpdateProp { value, .. } => {
            refs.insert(value.clone());
        }
        ANFValue::CheckPreimage { preimage } => {
            refs.insert(preimage.clone());
        }
        ANFValue::DeserializeState { preimage } => {
            refs.insert(preimage.clone());
        }
        ANFValue::AddOutput {
            satoshis,
            state_values,
            preimage,
        } => {
            refs.insert(satoshis.clone());
            for sv in state_values {
                refs.insert(sv.clone());
            }
            if !preimage.is_empty() {
                refs.insert(preimage.clone());
            }
        }
        ANFValue::AddRawOutput { satoshis, script_bytes } => {
            refs.insert(satoshis.clone());
            refs.insert(script_bytes.clone());
        }
        ANFValue::AddDataOutput { satoshis, script_bytes } => {
            refs.insert(satoshis.clone());
            refs.insert(script_bytes.clone());
        }
        ANFValue::ArrayLiteral { elements } => {
            for elem in elements {
                refs.insert(elem.clone());
            }
        }
    }
}

/// Returns true if the binding has side effects and must not be eliminated.
pub fn has_side_effect(value: &ANFValue) -> bool {
    matches!(
        value,
        ANFValue::Assert { .. }
            | ANFValue::UpdateProp { .. }
            | ANFValue::CheckPreimage { .. }
            | ANFValue::DeserializeState { .. }
            | ANFValue::AddOutput { .. }
            | ANFValue::AddRawOutput { .. }
            | ANFValue::AddDataOutput { .. }
            | ANFValue::MethodCall { .. }
            | ANFValue::Call { .. }
            // opaque byte span — DCE must never eliminate it
            | ANFValue::RawScript { .. }
    )
}
