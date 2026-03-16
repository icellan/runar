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
        ANFValue::LoadParam { .. } => {
            // Do NOT track @ref: targets here — matches TS collectRefsFromValue
            // which breaks on load_param without collecting refs.
        }
        ANFValue::LoadProp { .. } | ANFValue::GetStateScript {} => {}
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
        ANFValue::ArrayLiteral { elements } => {
            for elem in elements {
                refs.insert(elem.clone());
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_program(bindings: Vec<ANFBinding>) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body: bindings,
                is_public: true,
            }],
        }
    }

    fn load_const_hex(name: &str, hex: &str) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::LoadConst {
                value: serde_json::Value::String(hex.to_string()),
            },
        }
    }

    fn load_const_int(name: &str, n: i64) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::LoadConst {
                value: serde_json::json!(n),
            },
        }
    }

    fn call_binding(name: &str, func: &str, args: Vec<&str>) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::Call {
                func: func.to_string(),
                args: args.into_iter().map(|s| s.to_string()).collect(),
            },
        }
    }

    fn assert_binding(name: &str, value_ref: &str) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value: ANFValue::Assert {
                value: value_ref.to_string(),
            },
        }
    }

    fn find_binding<'a>(bindings: &'a [ANFBinding], name: &str) -> Option<&'a ANFBinding> {
        bindings.iter().find(|b| b.name == name)
    }

    fn get_method_body(program: &ANFProgram) -> &[ANFBinding] {
        &program.methods[0].body
    }

    fn infinity_hex() -> String {
        INFINITY_HEX.to_string()
    }

    fn g_hex() -> String {
        G_HEX.to_string()
    }

    fn some_point() -> String {
        "ab".repeat(64)
    }

    // -----------------------------------------------------------------------
    // Pass-through behavior (no EC ops)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pass_through_no_ec_ops() {
        let bindings = vec![
            load_const_int("t0", 42),
            load_const_int("t1", 10),
            ANFBinding {
                name: "t2".to_string(),
                value: ANFValue::BinOp {
                    op: "+".to_string(),
                    left: "t0".to_string(),
                    right: "t1".to_string(),
                    result_type: None,
                },
            },
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);

        let body = get_method_body(&result);
        assert_eq!(body.len(), 4, "expected 4 bindings, got {}", body.len());
        assert_eq!(body[0].name, "t0");
        assert_eq!(body[1].name, "t1");
        assert_eq!(body[2].name, "t2");
        assert_eq!(body[3].name, "t3");
    }

    #[test]
    fn test_pass_through_empty_method() {
        let program = make_program(vec![]);
        let result = optimize_ec(program);
        assert_eq!(get_method_body(&result).len(), 0);
    }

    // -----------------------------------------------------------------------
    // Rule 1: ecAdd(x, INFINITY) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule1_ec_add_x_infinity() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_hex("t1", &infinity_hex()),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 2: ecAdd(INFINITY, x) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule2_ec_add_infinity_x() {
        let bindings = vec![
            load_const_hex("t0", &infinity_hex()),
            load_const_hex("t1", &"cd".repeat(64)),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t1", "expected @ref:t1, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 3: ecMul(x, 1) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule3_ec_mul_by_one() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_int("t1", 1),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 4: ecMul(x, 0) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule4_ec_mul_by_zero() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_int("t1", 0),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 5: ecMulGen(0) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule5_ec_mulgen_zero() {
        let bindings = vec![
            load_const_int("t0", 0),
            call_binding("t1", "ecMulGen", vec!["t0"]),
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected binding t1");
        match &t1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 6: ecMulGen(1) -> G
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule6_ec_mulgen_one() {
        let bindings = vec![
            load_const_int("t0", 1),
            call_binding("t1", "ecMulGen", vec!["t0"]),
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected binding t1");
        match &t1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(G_HEX),
                    "expected G, got {value}"
                );
            }
            other => panic!("expected LoadConst(G), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 7: ecNegate(ecNegate(x)) -> alias to x
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule7_double_negate() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            call_binding("t1", "ecNegate", vec!["t0"]),
            call_binding("t2", "ecNegate", vec!["t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                let name = value.as_str().unwrap();
                assert_eq!(name, "@ref:t0", "expected @ref:t0, got {name}");
            }
            other => panic!("expected LoadConst, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule8_add_negate() {
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            call_binding("t1", "ecNegate", vec!["t0"]),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(
                    value.as_str(),
                    Some(INFINITY_HEX),
                    "expected INFINITY, got {value}"
                );
            }
            other => panic!("expected LoadConst(INFINITY), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Rule 12: ecMul(G, k) -> ecMulGen(k)
    // -----------------------------------------------------------------------

    #[test]
    fn test_rule12_mul_g_to_mulgen() {
        let bindings = vec![
            load_const_hex("t0", &g_hex()),
            load_const_int("t1", 42),
            call_binding("t2", "ecMul", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t2 = find_binding(body, "t2").expect("expected binding t2");
        match &t2.value {
            ANFValue::Call { func, args } => {
                assert_eq!(func, "ecMulGen", "expected ecMulGen, got {func}");
                assert_eq!(args, &["t1"], "expected args [t1], got {args:?}");
            }
            other => panic!("expected Call(ecMulGen), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Dead binding elimination
    // -----------------------------------------------------------------------

    #[test]
    fn test_dead_binding_removed() {
        // ecAdd(t0, INFINITY) rewrites t2 to @ref:t0.
        // t1 (INFINITY constant) is then unreferenced and should be removed.
        let bindings = vec![
            load_const_hex("t0", &some_point()),
            load_const_hex("t1", &infinity_hex()),
            call_binding("t2", "ecAdd", vec!["t0", "t1"]),
            assert_binding("t3", "t2"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let names: Vec<&str> = body.iter().map(|b| b.name.as_str()).collect();
        assert!(
            !names.contains(&"t1"),
            "expected dead binding t1 (INFINITY) to be eliminated, but it is still present"
        );
    }

    // -----------------------------------------------------------------------
    // Non-EC builtins pass through unchanged
    // -----------------------------------------------------------------------

    #[test]
    fn test_non_ec_call_unchanged() {
        // hash160 is not an EC intrinsic — it must survive the optimizer intact.
        let bindings = vec![
            load_const_hex("t0", &"ab".repeat(33)),
            ANFBinding {
                name: "t1".to_string(),
                value: ANFValue::Call {
                    func: "hash160".to_string(),
                    args: vec!["t0".to_string()],
                },
            },
            assert_binding("t2", "t1"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let t1 = find_binding(body, "t1").expect("expected hash160 binding t1 to be present");
        match &t1.value {
            ANFValue::Call { func, args } => {
                assert_eq!(func, "hash160", "expected hash160 call preserved, got {func}");
                assert_eq!(args, &["t0"], "expected args [t0], got {args:?}");
            }
            other => panic!("expected Call(hash160), got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Side-effect bindings survive dead-binding elimination
    // -----------------------------------------------------------------------

    #[test]
    fn test_side_effect_bindings_preserved() {
        // An assert binding whose result is never referenced must not be
        // eliminated by dead-binding elimination, because it has a side effect.
        let bindings = vec![
            load_const_int("t0", 1),
            // assert is a side effect — must not be eliminated even if unreferenced
            assert_binding("t1", "t0"),
        ];
        let program = make_program(bindings);
        let result = optimize_ec(program);
        let body = get_method_body(&result);

        let names: Vec<&str> = body.iter().map(|b| b.name.as_str()).collect();
        assert!(
            names.contains(&"t1"),
            "expected assert binding t1 to be preserved as side effect, but it was eliminated. bindings: {names:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Program structure preserved
    // -----------------------------------------------------------------------

    #[test]
    fn test_contract_name_preserved() {
        let program = ANFProgram {
            contract_name: "MyContract".to_string(),
            properties: vec![ANFProperty {
                name: "x".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: None,
            }],
            methods: vec![ANFMethod {
                name: "doStuff".to_string(),
                params: vec![ANFParam {
                    name: "y".to_string(),
                    param_type: "bigint".to_string(),
                }],
                body: vec![
                    load_const_int("t0", 1),
                    assert_binding("t1", "t0"),
                ],
                is_public: true,
            }],
        };

        let result = optimize_ec(program);

        assert_eq!(result.contract_name, "MyContract");
        assert_eq!(result.properties.len(), 1);
        assert_eq!(result.properties[0].name, "x");
        assert_eq!(result.methods.len(), 1);
        assert_eq!(result.methods[0].name, "doStuff");
    }

    #[test]
    fn test_multiple_methods_all_optimized() {
        let program = ANFProgram {
            contract_name: "Test".to_string(),
            properties: vec![],
            methods: vec![
                ANFMethod {
                    name: "method1".to_string(),
                    params: vec![],
                    body: vec![
                        load_const_int("t0", 0),
                        call_binding("t1", "ecMulGen", vec!["t0"]),
                        assert_binding("t2", "t1"),
                    ],
                    is_public: true,
                },
                ANFMethod {
                    name: "method2".to_string(),
                    params: vec![],
                    body: vec![
                        load_const_int("t0", 1),
                        call_binding("t1", "ecMulGen", vec!["t0"]),
                        assert_binding("t2", "t1"),
                    ],
                    is_public: true,
                },
            ],
        };

        let result = optimize_ec(program);

        assert_eq!(result.methods.len(), 2);

        // method1: ecMulGen(0) -> INFINITY
        let body1 = &result.methods[0].body;
        let t1m1 = find_binding(body1, "t1").expect("expected t1 in method1");
        match &t1m1.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(value.as_str(), Some(INFINITY_HEX), "method1 t1: expected INFINITY");
            }
            other => panic!("method1 t1: expected LoadConst(INFINITY), got {other:?}"),
        }

        // method2: ecMulGen(1) -> G
        let body2 = &result.methods[1].body;
        let t1m2 = find_binding(body2, "t1").expect("expected t1 in method2");
        match &t1m2.value {
            ANFValue::LoadConst { value } => {
                assert_eq!(value.as_str(), Some(G_HEX), "method2 t1: expected G");
            }
            other => panic!("method2 t1: expected LoadConst(G), got {other:?}"),
        }
    }
}
