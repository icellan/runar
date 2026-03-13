//! ANF EC Optimizer (Pass 4.5) — algebraic simplification of EC operations.
//!
//! Runs on ANF IR BEFORE stack lowering. Each eliminated ecMul saves ~1500 bytes,
//! each eliminated ecAdd saves ~800 bytes. Always-on.
//!
//! Mirrors the TypeScript optimizer in `packages/runar-compiler/src/optimizer/anf-ec.ts`.

use std::collections::{HashMap, HashSet};

use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue};

// ---------------------------------------------------------------------------
// EC constants
// ---------------------------------------------------------------------------

/// Point at infinity: 64 zero bytes as hex.
const INFINITY_HEX: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Generator point G as 64-byte hex (x || y, big-endian unsigned, no prefix).
const G_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

// ---------------------------------------------------------------------------
// Value resolution helpers (uses owned ANFValue map for borrow-checker safety)
// ---------------------------------------------------------------------------

type ValueMap = HashMap<String, ANFValue>;

fn is_call_to<'a>(value: &'a ANFValue, func_name: &str) -> Option<&'a Vec<String>> {
    match value {
        ANFValue::Call { func, args } if func == func_name => Some(args),
        _ => None,
    }
}

fn is_const_int(value: &ANFValue, n: i128) -> bool {
    match value {
        ANFValue::LoadConst { value: v } => {
            if let Some(i) = v.as_i64() {
                return i as i128 == n;
            }
            if let Some(f) = v.as_f64() {
                return f as i128 == n;
            }
            false
        }
        _ => false,
    }
}

fn get_const_int(value: &ANFValue) -> Option<i128> {
    match value {
        ANFValue::LoadConst { value: v } => {
            if let Some(i) = v.as_i64() {
                return Some(i as i128);
            }
            if let Some(f) = v.as_f64() {
                let i = f as i128;
                if (i as f64) == f {
                    return Some(i);
                }
            }
            None
        }
        _ => None,
    }
}

fn is_const_hex(value: &ANFValue, hex: &str) -> bool {
    match value {
        ANFValue::LoadConst { value: v } => v.as_str() == Some(hex),
        _ => false,
    }
}

fn is_infinity(value: &ANFValue) -> bool {
    is_const_hex(value, INFINITY_HEX)
}

fn is_generator_point(value: &ANFValue) -> bool {
    is_const_hex(value, G_HEX)
}

/// Check if a resolved arg represents the infinity point.
fn arg_is_infinity(arg_name: &str, value_map: &ValueMap) -> bool {
    let v = match value_map.get(arg_name) {
        Some(v) => v,
        None => return false,
    };
    if is_infinity(v) {
        return true;
    }
    // ecMulGen(0) = infinity
    if let Some(args) = is_call_to(v, "ecMulGen") {
        if args.len() == 1 {
            if let Some(scalar_val) = value_map.get(args[0].as_str()) {
                if is_const_int(scalar_val, 0) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if a resolved arg represents the generator point G.
fn arg_is_g(arg_name: &str, value_map: &ValueMap) -> bool {
    let v = match value_map.get(arg_name) {
        Some(v) => v,
        None => return false,
    };
    if is_generator_point(v) {
        return true;
    }
    // ecMulGen(1) = G
    if let Some(args) = is_call_to(v, "ecMulGen") {
        if args.len() == 1 {
            if let Some(scalar_val) = value_map.get(args[0].as_str()) {
                if is_const_int(scalar_val, 1) {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Rewrite helpers
// ---------------------------------------------------------------------------

fn make_load_const_hex(hex: &str) -> ANFValue {
    ANFValue::LoadConst {
        value: serde_json::Value::String(hex.to_string()),
    }
}

fn make_load_const_int(n: i128) -> ANFValue {
    ANFValue::LoadConst {
        value: serde_json::json!(n as i64),
    }
}

fn make_alias(target: &str) -> ANFValue {
    ANFValue::LoadConst {
        value: serde_json::Value::String(format!("@ref:{}", target)),
    }
}

// ---------------------------------------------------------------------------
// Rewrite engine
// ---------------------------------------------------------------------------

/// Try to rewrite a single binding. Returns Some(new_value) if rewritten.
/// May push extra bindings (e.g., computed scalars) into `extra_bindings`.
fn try_rewrite(
    binding: &ANFBinding,
    value_map: &ValueMap,
    extra_bindings: &mut Vec<ANFBinding>,
) -> Option<ANFValue> {
    let value = &binding.value;

    let (func, args) = match value {
        ANFValue::Call { func, args } => (func.as_str(), args),
        _ => return None,
    };

    match func {
        "ecMulGen" => {
            if args.len() != 1 {
                return None;
            }
            let scalar_val = value_map.get(args[0].as_str())?;

            // Rule 5: ecMulGen(0) -> INFINITY
            if is_const_int(scalar_val, 0) {
                return Some(make_load_const_hex(INFINITY_HEX));
            }

            // Rule 6: ecMulGen(1) -> G
            if is_const_int(scalar_val, 1) {
                return Some(make_load_const_hex(G_HEX));
            }

            None
        }

        "ecMul" => {
            if args.len() != 2 {
                return None;
            }
            let point_arg = &args[0];
            let scalar_arg = &args[1];
            let scalar_val = value_map.get(scalar_arg.as_str())?;

            // Rule 4: ecMul(x, 0) -> INFINITY
            if is_const_int(scalar_val, 0) {
                return Some(make_load_const_hex(INFINITY_HEX));
            }

            // Rule 3: ecMul(x, 1) -> x (alias)
            if is_const_int(scalar_val, 1) {
                return Some(make_alias(point_arg));
            }

            // Rule 12: ecMul(G, k) -> ecMulGen(k)
            if arg_is_g(point_arg, value_map) {
                return Some(ANFValue::Call {
                    func: "ecMulGen".to_string(),
                    args: vec![scalar_arg.clone()],
                });
            }

            // Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2)
            if let Some(point_val) = value_map.get(point_arg.as_str()) {
                if let Some(inner_args) = is_call_to(point_val, "ecMul") {
                    if inner_args.len() == 2 {
                        let inner_point = inner_args[0].clone();
                        let inner_scalar = inner_args[1].clone();
                        if let Some(inner_scalar_val) = value_map.get(inner_scalar.as_str()) {
                            let k1 = get_const_int(inner_scalar_val);
                            let k2 = get_const_int(scalar_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                // Only fold if product doesn't overflow i128
                                if let Some(product) = k1.checked_mul(k2) {
                                    let new_scalar_name = format!("{}_k", binding.name);
                                    extra_bindings.push(ANFBinding {
                                        name: new_scalar_name.clone(),
                                        value: make_load_const_int(product),
                                    });
                                    return Some(ANFValue::Call {
                                        func: "ecMul".to_string(),
                                        args: vec![inner_point, new_scalar_name],
                                    });
                                }
                            }
                        }
                    }
                }
            }

            None
        }

        "ecAdd" => {
            if args.len() != 2 {
                return None;
            }
            let left_arg = &args[0];
            let right_arg = &args[1];

            // Rule 1: ecAdd(x, INFINITY) -> x
            if arg_is_infinity(right_arg, value_map) {
                return Some(make_alias(left_arg));
            }

            // Rule 2: ecAdd(INFINITY, x) -> x
            if arg_is_infinity(left_arg, value_map) {
                return Some(make_alias(right_arg));
            }

            // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
            if let Some(right_val) = value_map.get(right_arg.as_str()) {
                if let Some(negate_args) = is_call_to(right_val, "ecNegate") {
                    if negate_args.len() == 1 && negate_args[0] == *left_arg {
                        return Some(make_load_const_hex(INFINITY_HEX));
                    }
                }
            }

            // Rules 10 & 11 require looking up both sides
            let left_val = value_map.get(left_arg.as_str()).cloned();
            let right_val = value_map.get(right_arg.as_str()).cloned();

            if let (Some(ref lv), Some(ref rv)) = (&left_val, &right_val) {
                // Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2)
                if let (Some(left_args), Some(right_args)) =
                    (is_call_to(lv, "ecMulGen"), is_call_to(rv, "ecMulGen"))
                {
                    if left_args.len() == 1 && right_args.len() == 1 {
                        let k1_name = left_args[0].clone();
                        let k2_name = right_args[0].clone();
                        if let (Some(k1_val), Some(k2_val)) = (
                            value_map.get(k1_name.as_str()),
                            value_map.get(k2_name.as_str()),
                        ) {
                            let k1 = get_const_int(k1_val);
                            let k2 = get_const_int(k2_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                if let Some(sum) = k1.checked_add(k2) {
                                    let new_scalar_name = format!("{}_k", binding.name);
                                    extra_bindings.push(ANFBinding {
                                        name: new_scalar_name.clone(),
                                        value: make_load_const_int(sum),
                                    });
                                    return Some(ANFValue::Call {
                                        func: "ecMulGen".to_string(),
                                        args: vec![new_scalar_name],
                                    });
                                }
                            }
                        }
                    }
                }

                // Rule 11: ecAdd(ecMul(p, k1), ecMul(p, k2)) -> ecMul(p, k1+k2)
                if let (Some(left_mul_args), Some(right_mul_args)) =
                    (is_call_to(lv, "ecMul"), is_call_to(rv, "ecMul"))
                {
                    if left_mul_args.len() == 2
                        && right_mul_args.len() == 2
                        && left_mul_args[0] == right_mul_args[0]
                    {
                        let point_name = left_mul_args[0].clone();
                        let k1_name = left_mul_args[1].clone();
                        let k2_name = right_mul_args[1].clone();
                        if let (Some(k1_val), Some(k2_val)) = (
                            value_map.get(k1_name.as_str()),
                            value_map.get(k2_name.as_str()),
                        ) {
                            let k1 = get_const_int(k1_val);
                            let k2 = get_const_int(k2_val);
                            if let (Some(k1), Some(k2)) = (k1, k2) {
                                if let Some(sum) = k1.checked_add(k2) {
                                    let new_scalar_name = format!("{}_k", binding.name);
                                    extra_bindings.push(ANFBinding {
                                        name: new_scalar_name.clone(),
                                        value: make_load_const_int(sum),
                                    });
                                    return Some(ANFValue::Call {
                                        func: "ecMul".to_string(),
                                        args: vec![point_name, new_scalar_name],
                                    });
                                }
                            }
                        }
                    }
                }
            }

            None
        }

        "ecNegate" => {
            if args.len() != 1 {
                return None;
            }
            let inner_val = value_map.get(args[0].as_str())?;

            // Rule 7: ecNegate(ecNegate(x)) -> x
            if let Some(negate_args) = is_call_to(inner_val, "ecNegate") {
                if negate_args.len() == 1 {
                    return Some(make_alias(&negate_args[0]));
                }
            }

            None
        }

        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Dead binding elimination
// ---------------------------------------------------------------------------

/// Collect all referenced binding names from a value.
fn collect_refs_from_value(value: &ANFValue, refs: &mut HashSet<String>) {
    match value {
        ANFValue::LoadParam { name } => {
            // Handle @ref: aliases
            if let Some(target) = name.strip_prefix("@ref:") {
                refs.insert(target.to_string());
            } else {
                refs.insert(name.clone());
            }
        }
        ANFValue::LoadProp { .. } | ANFValue::GetStateScript {} => {}
        ANFValue::LoadConst { value: v } => {
            // @ref: values reference another binding — must be tracked as a ref
            if let Some(s) = v.as_str() {
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
        ANFValue::Assert { value } => {
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
        ANFValue::SnarkVerify { proof, public_inputs } => {
            refs.insert(proof.clone());
            for input in public_inputs {
                refs.insert(input.clone());
            }
        }
    }
}

/// Returns true if the binding has side effects and must not be eliminated.
fn has_side_effect(value: &ANFValue) -> bool {
    matches!(
        value,
        ANFValue::Assert { .. }
            | ANFValue::UpdateProp { .. }
            | ANFValue::CheckPreimage { .. }
            | ANFValue::DeserializeState { .. }
            | ANFValue::AddOutput { .. }
            | ANFValue::AddRawOutput { .. }
            | ANFValue::SnarkVerify { .. }
            | ANFValue::MethodCall { .. }
            | ANFValue::Call { .. }
    )
}

/// Eliminate dead (unreferenced, side-effect-free) bindings, iterating to fixed point.
fn eliminate_dead_bindings_method(method: &ANFMethod) -> ANFMethod {
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
// Method optimizer
// ---------------------------------------------------------------------------

fn optimize_method_ec(method: &ANFMethod) -> (ANFMethod, bool) {
    let mut value_map: ValueMap = HashMap::new();
    let mut result: Vec<ANFBinding> = Vec::new();
    let mut changed = false;

    for binding in &method.body {
        // Register binding value for lookups
        value_map.insert(binding.name.clone(), binding.value.clone());

        let mut extra_bindings = Vec::new();
        let rewritten = try_rewrite(binding, &value_map, &mut extra_bindings);

        if let Some(new_value) = rewritten {
            // Add any new helper bindings (e.g., computed scalars)
            for extra in &extra_bindings {
                value_map.insert(extra.name.clone(), extra.value.clone());
                result.push(extra.clone());
            }
            // Update the value map with the rewritten value
            value_map.insert(binding.name.clone(), new_value.clone());
            result.push(ANFBinding {
                name: binding.name.clone(),
                value: new_value,
            });
            changed = true;
        } else {
            result.push(binding.clone());
        }
    }

    if !changed {
        return (method.clone(), false);
    }

    (ANFMethod {
        name: method.name.clone(),
        params: method.params.clone(),
        body: result,
        is_public: method.is_public,
    }, true)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Optimize EC operations in an ANF program (Pass 4.5).
///
/// Applies algebraic simplification rules to EC function calls,
/// then eliminates dead bindings. Always-on, runs before stack lowering.
pub fn optimize_ec(program: ANFProgram) -> ANFProgram {
    let mut any_changed = false;
    let optimized_methods: Vec<ANFMethod> = program
        .methods
        .iter()
        .map(|m| {
            let (opt, changed) = optimize_method_ec(m);
            if changed {
                any_changed = true;
            }
            opt
        })
        .collect();

    if !any_changed {
        return program;
    }

    // Run dead binding elimination to clean up orphaned bindings
    let cleaned_methods: Vec<ANFMethod> = optimized_methods
        .iter()
        .map(eliminate_dead_bindings_method)
        .collect();

    ANFProgram {
        contract_name: program.contract_name,
        properties: program.properties,
        methods: cleaned_methods,
    }
}
