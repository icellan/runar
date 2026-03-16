//! Constant folding pass for ANF IR.
//!
//! Evaluates compile-time-known expressions and replaces them with `load_const`
//! bindings. Constants are propagated through the binding chain so downstream
//! operations can be folded too.

use std::collections::HashMap;

use crate::ir::{ANFBinding, ANFMethod, ANFProgram, ANFValue, ConstValue};

// ---------------------------------------------------------------------------
// Constant environment
// ---------------------------------------------------------------------------

type ConstEnv = HashMap<String, ConstValue>;

fn env_clone(env: &ConstEnv) -> ConstEnv {
    env.clone()
}

// ---------------------------------------------------------------------------
// Binary operation evaluation
// ---------------------------------------------------------------------------

fn eval_bin_op(op: &str, left: &ConstValue, right: &ConstValue) -> Option<ConstValue> {
    // Arithmetic/bitwise/comparison on ints
    if let (ConstValue::Int(a), ConstValue::Int(b)) = (left, right) {
        return match op {
            "+" => a.checked_add(*b).map(ConstValue::Int),
            "-" => a.checked_sub(*b).map(ConstValue::Int),
            "*" => a.checked_mul(*b).map(ConstValue::Int),
            "/" => {
                if *b == 0 {
                    None
                } else {
                    // Truncated division (toward zero), matching JS BigInt semantics
                    Some(ConstValue::Int(a / b))
                }
            }
            "%" => {
                if *b == 0 {
                    None
                } else {
                    // Remainder matching JS BigInt (sign follows dividend)
                    Some(ConstValue::Int(a % b))
                }
            }
            "===" => Some(ConstValue::Bool(a == b)),
            "!==" => Some(ConstValue::Bool(a != b)),
            "<" => Some(ConstValue::Bool(a < b)),
            ">" => Some(ConstValue::Bool(a > b)),
            "<=" => Some(ConstValue::Bool(a <= b)),
            ">=" => Some(ConstValue::Bool(a >= b)),
            "&" => Some(ConstValue::Int(a & b)),
            "|" => Some(ConstValue::Int(a | b)),
            "^" => Some(ConstValue::Int(a ^ b)),
            "<<" => {
                if *a < 0 {
                    return None; // skip for negative left operand (BSV shifts are logical)
                }
                if *b < 0 || *b > 128 {
                    return None;
                }
                a.checked_shl(*b as u32).map(ConstValue::Int)
            }
            ">>" => {
                if *a < 0 {
                    return None; // skip for negative left operand (BSV shifts are logical)
                }
                if *b < 0 || *b > 128 {
                    return None;
                }
                Some(ConstValue::Int(a >> (*b as u32)))
            }
            _ => None,
        };
    }

    // Boolean operations
    if let (ConstValue::Bool(a), ConstValue::Bool(b)) = (left, right) {
        return match op {
            "&&" => Some(ConstValue::Bool(*a && *b)),
            "||" => Some(ConstValue::Bool(*a || *b)),
            "===" => Some(ConstValue::Bool(a == b)),
            "!==" => Some(ConstValue::Bool(a != b)),
            _ => None,
        };
    }

    // String (ByteString) operations
    if let (ConstValue::Str(a), ConstValue::Str(b)) = (left, right) {
        return match op {
            "+" => {
                if !is_valid_hex(a) || !is_valid_hex(b) {
                    None
                } else {
                    Some(ConstValue::Str(format!("{}{}", a, b)))
                }
            }
            "===" => Some(ConstValue::Bool(a == b)),
            "!==" => Some(ConstValue::Bool(a != b)),
            _ => None,
        };
    }

    // Cross-type equality
    if op == "===" {
        return Some(ConstValue::Bool(false));
    }
    if op == "!==" {
        return Some(ConstValue::Bool(true));
    }

    None
}

fn is_valid_hex(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Unary operation evaluation
// ---------------------------------------------------------------------------

fn eval_unary_op(op: &str, operand: &ConstValue) -> Option<ConstValue> {
    match operand {
        ConstValue::Bool(b) => match op {
            "!" => Some(ConstValue::Bool(!b)),
            _ => None,
        },
        ConstValue::Int(n) => match op {
            "-" => Some(ConstValue::Int(-n)),
            "~" => Some(ConstValue::Int(!n)),
            "!" => Some(ConstValue::Bool(*n == 0)),
            _ => None,
        },
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Builtin call evaluation (pure math functions only)
// ---------------------------------------------------------------------------

fn eval_builtin_call(func_name: &str, args: &[&ConstValue]) -> Option<ConstValue> {
    // Only fold pure math builtins with int arguments
    let int_args: Vec<i128> = args
        .iter()
        .map(|a| match a {
            ConstValue::Int(n) => Some(*n),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;

    match func_name {
        "abs" => {
            if int_args.len() != 1 {
                return None;
            }
            Some(ConstValue::Int(int_args[0].abs()))
        }
        "min" => {
            if int_args.len() != 2 {
                return None;
            }
            Some(ConstValue::Int(int_args[0].min(int_args[1])))
        }
        "max" => {
            if int_args.len() != 2 {
                return None;
            }
            Some(ConstValue::Int(int_args[0].max(int_args[1])))
        }
        "safediv" => {
            if int_args.len() != 2 || int_args[1] == 0 {
                return None;
            }
            Some(ConstValue::Int(int_args[0] / int_args[1]))
        }
        "safemod" => {
            if int_args.len() != 2 || int_args[1] == 0 {
                return None;
            }
            Some(ConstValue::Int(int_args[0] % int_args[1]))
        }
        "clamp" => {
            if int_args.len() != 3 {
                return None;
            }
            let (val, lo, hi) = (int_args[0], int_args[1], int_args[2]);
            Some(ConstValue::Int(val.max(lo).min(hi)))
        }
        "sign" => {
            if int_args.len() != 1 {
                return None;
            }
            Some(ConstValue::Int(int_args[0].signum()))
        }
        "pow" => {
            if int_args.len() != 2 {
                return None;
            }
            let (base, exp) = (int_args[0], int_args[1]);
            if exp < 0 || exp > 256 {
                return None;
            }
            let mut result: i128 = 1;
            for _ in 0..exp {
                result = result.checked_mul(base)?;
            }
            Some(ConstValue::Int(result))
        }
        "mulDiv" => {
            if int_args.len() != 3 || int_args[2] == 0 {
                return None;
            }
            let tmp = int_args[0].checked_mul(int_args[1])?;
            Some(ConstValue::Int(tmp / int_args[2]))
        }
        "percentOf" => {
            if int_args.len() != 2 {
                return None;
            }
            let tmp = int_args[0].checked_mul(int_args[1])?;
            Some(ConstValue::Int(tmp / 10000))
        }
        "sqrt" => {
            if int_args.len() != 1 {
                return None;
            }
            let n = int_args[0];
            if n < 0 {
                return None;
            }
            if n == 0 {
                return Some(ConstValue::Int(0));
            }
            // Integer square root via Newton's method
            let mut x = n;
            let mut y = (x + 1) / 2;
            while y < x {
                x = y;
                y = (x + n / x) / 2;
            }
            Some(ConstValue::Int(x))
        }
        "gcd" => {
            if int_args.len() != 2 {
                return None;
            }
            let mut a = int_args[0].abs();
            let mut b = int_args[1].abs();
            while b != 0 {
                let t = b;
                b = a % b;
                a = t;
            }
            Some(ConstValue::Int(a))
        }
        "divmod" => {
            if int_args.len() != 2 || int_args[1] == 0 {
                return None;
            }
            Some(ConstValue::Int(int_args[0] / int_args[1]))
        }
        "log2" => {
            if int_args.len() != 1 {
                return None;
            }
            let n = int_args[0];
            if n <= 0 {
                return Some(ConstValue::Int(0));
            }
            Some(ConstValue::Int(127 - n.leading_zeros() as i128))
        }
        "bool" => {
            if int_args.len() != 1 {
                return None;
            }
            Some(ConstValue::Bool(int_args[0] != 0))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ANF Value <-> ConstValue conversion
// ---------------------------------------------------------------------------

fn anf_value_to_const(value: &ANFValue) -> Option<ConstValue> {
    match value {
        ANFValue::LoadConst { value: v } => {
            // Skip @ref: aliases — they are binding references, not real constants
            if let serde_json::Value::String(s) = v {
                if s.starts_with("@ref:") {
                    return None;
                }
            }
            crate::ir::parse_const_value(v)
        }
        _ => None,
    }
}

fn const_to_anf_value(cv: &ConstValue) -> ANFValue {
    match cv {
        ConstValue::Int(n) => ANFValue::LoadConst {
            value: serde_json::Value::Number(serde_json::Number::from(*n as i64)),
        },
        ConstValue::Bool(b) => ANFValue::LoadConst {
            value: serde_json::Value::Bool(*b),
        },
        ConstValue::Str(s) => ANFValue::LoadConst {
            value: serde_json::Value::String(s.clone()),
        },
    }
}

// ---------------------------------------------------------------------------
// Fold bindings
// ---------------------------------------------------------------------------

fn fold_bindings(bindings: &[ANFBinding], env: &mut ConstEnv) -> Vec<ANFBinding> {
    bindings
        .iter()
        .map(|b| fold_binding(b, env))
        .collect()
}

fn fold_binding(binding: &ANFBinding, env: &mut ConstEnv) -> ANFBinding {
    let folded_value = fold_value(&binding.value, env);

    // If the folded value is a load_const, register in the environment
    if let Some(cv) = anf_value_to_const(&folded_value) {
        env.insert(binding.name.clone(), cv);
    }

    ANFBinding {
        name: binding.name.clone(),
        value: folded_value,
    }
}

// ---------------------------------------------------------------------------
// Fold a single value
// ---------------------------------------------------------------------------

fn fold_value(value: &ANFValue, env: &mut ConstEnv) -> ANFValue {
    match value {
        ANFValue::LoadConst { .. } | ANFValue::LoadParam { .. } | ANFValue::LoadProp { .. } => {
            value.clone()
        }

        ANFValue::BinOp {
            op,
            left,
            right,
            result_type: _,
        } => {
            let left_const = env.get(left);
            let right_const = env.get(right);
            if let (Some(lc), Some(rc)) = (left_const, right_const) {
                if let Some(result) = eval_bin_op(op, lc, rc) {
                    return const_to_anf_value(&result);
                }
            }
            value.clone()
        }

        ANFValue::UnaryOp {
            op,
            operand,
            result_type: _,
        } => {
            if let Some(oc) = env.get(operand) {
                if let Some(result) = eval_unary_op(op, oc) {
                    return const_to_anf_value(&result);
                }
            }
            value.clone()
        }

        ANFValue::Call { func, args } => {
            let all_const = args.iter().all(|a| env.contains_key(a));
            if all_const {
                let const_args: Vec<&ConstValue> = args.iter().map(|a| env.get(a).unwrap()).collect();
                if let Some(folded) = eval_builtin_call(func, &const_args) {
                    return const_to_anf_value(&folded);
                }
            }
            value.clone()
        }

        ANFValue::MethodCall { .. } => value.clone(),

        ANFValue::If {
            cond,
            then,
            else_branch,
        } => {
            if let Some(ConstValue::Bool(cond_val)) = env.get(cond) {
                let cond_val = *cond_val;
                if cond_val {
                    let mut then_env = env_clone(env);
                    let folded_then = fold_bindings(then, &mut then_env);
                    // Merge constants from taken branch back into env
                    for b in &folded_then {
                        if let Some(cv) = anf_value_to_const(&b.value) {
                            env.insert(b.name.clone(), cv);
                        }
                    }
                    ANFValue::If {
                        cond: cond.clone(),
                        then: folded_then,
                        else_branch: vec![],
                    }
                } else {
                    let mut else_env = env_clone(env);
                    let folded_else = fold_bindings(else_branch, &mut else_env);
                    for b in &folded_else {
                        if let Some(cv) = anf_value_to_const(&b.value) {
                            env.insert(b.name.clone(), cv);
                        }
                    }
                    ANFValue::If {
                        cond: cond.clone(),
                        then: vec![],
                        else_branch: folded_else,
                    }
                }
            } else {
                // Condition not known — fold both branches independently
                let mut then_env = env_clone(env);
                let mut else_env = env_clone(env);
                let folded_then = fold_bindings(then, &mut then_env);
                let folded_else = fold_bindings(else_branch, &mut else_env);
                ANFValue::If {
                    cond: cond.clone(),
                    then: folded_then,
                    else_branch: folded_else,
                }
            }
        }

        ANFValue::Loop {
            count,
            body,
            iter_var,
        } => {
            let mut body_env = env_clone(env);
            let folded_body = fold_bindings(body, &mut body_env);
            ANFValue::Loop {
                count: *count,
                body: folded_body,
                iter_var: iter_var.clone(),
            }
        }

        // Terminal / side-effecting kinds pass through
        ANFValue::Assert { .. }
        | ANFValue::UpdateProp { .. }
        | ANFValue::GetStateScript { .. }
        | ANFValue::CheckPreimage { .. }
        | ANFValue::DeserializeState { .. }
        | ANFValue::AddOutput { .. }
        | ANFValue::AddRawOutput { .. }
        | ANFValue::ArrayLiteral { .. } => value.clone(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

fn fold_method(method: &ANFMethod) -> ANFMethod {
    let mut env = ConstEnv::new();
    let folded_body = fold_bindings(&method.body, &mut env);
    ANFMethod {
        name: method.name.clone(),
        params: method.params.clone(),
        body: folded_body,
        is_public: method.is_public,
    }
}

/// Apply constant folding to an ANF program.
///
/// Evaluates compile-time-known expressions and replaces them with
/// `load_const` bindings. Does NOT run dead binding elimination —
/// that is handled separately by the EC optimizer's DCE pass.
pub fn fold_constants(program: &ANFProgram) -> ANFProgram {
    ANFProgram {
        contract_name: program.contract_name.clone(),
        properties: program.properties.clone(),
        methods: program.methods.iter().map(|m| fold_method(m)).collect(),
    }
}

/// Apply constant folding without dead binding elimination.
/// Public for testing.
pub fn fold_constants_only(program: &ANFProgram) -> ANFProgram {
    fold_constants(program)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFBinding, ANFMethod, ANFParam, ANFProgram, ANFProperty, ANFValue};

    fn make_program(methods: Vec<ANFMethod>) -> ANFProgram {
        ANFProgram {
            contract_name: "Test".to_string(),
            properties: vec![],
            methods,
        }
    }

    fn make_method(name: &str, body: Vec<ANFBinding>) -> ANFMethod {
        ANFMethod {
            name: name.to_string(),
            params: vec![],
            body,
            is_public: true,
        }
    }

    fn b(name: &str, value: ANFValue) -> ANFBinding {
        ANFBinding {
            name: name.to_string(),
            value,
        }
    }

    fn mk_int(n: i128) -> ANFValue {
        ANFValue::LoadConst {
            value: serde_json::json!(n as i64),
        }
    }

    fn mk_bool(v: bool) -> ANFValue {
        ANFValue::LoadConst {
            value: serde_json::json!(v),
        }
    }

    fn mk_str(s: &str) -> ANFValue {
        ANFValue::LoadConst {
            value: serde_json::json!(s),
        }
    }

    fn bin_op(op: &str, left: &str, right: &str) -> ANFValue {
        ANFValue::BinOp {
            op: op.to_string(),
            left: left.to_string(),
            right: right.to_string(),
            result_type: None,
        }
    }

    fn unary_op(op: &str, operand: &str) -> ANFValue {
        ANFValue::UnaryOp {
            op: op.to_string(),
            operand: operand.to_string(),
            result_type: None,
        }
    }

    fn load_param(name: &str) -> ANFValue {
        ANFValue::LoadParam {
            name: name.to_string(),
        }
    }

    fn call_func(name: &str, args: Vec<&str>) -> ANFValue {
        ANFValue::Call {
            func: name.to_string(),
            args: args.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn assert_load_const_int(value: &ANFValue, expected: i128) {
        match value {
            ANFValue::LoadConst { value: v } => {
                let n = v.as_i64().expect("expected i64");
                assert_eq!(n as i128, expected, "expected {}, got {}", expected, n);
            }
            _ => panic!("expected LoadConst, got {:?}", value),
        }
    }

    fn assert_load_const_bool(value: &ANFValue, expected: bool) {
        match value {
            ANFValue::LoadConst { value: v } => {
                let b = v.as_bool().expect("expected bool");
                assert_eq!(b, expected);
            }
            _ => panic!("expected LoadConst, got {:?}", value),
        }
    }

    fn assert_load_const_str(value: &ANFValue, expected: &str) {
        match value {
            ANFValue::LoadConst { value: v } => {
                let s = v.as_str().expect("expected string");
                assert_eq!(s, expected);
            }
            _ => panic!("expected LoadConst, got {:?}", value),
        }
    }

    fn assert_not_folded(value: &ANFValue, expected_kind: &str) {
        let kind = match value {
            ANFValue::BinOp { .. } => "bin_op",
            ANFValue::UnaryOp { .. } => "unary_op",
            ANFValue::Call { .. } => "call",
            ANFValue::LoadParam { .. } => "load_param",
            ANFValue::LoadProp { .. } => "load_prop",
            ANFValue::LoadConst { .. } => "load_const",
            _ => "other",
        };
        assert_eq!(kind, expected_kind, "expected {}, got {:?}", expected_kind, value);
    }

    // -----------------------------------------------------------------------
    // 1. Binary operations on integers
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_addition() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(20)),
            b("t2", bin_op("+", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 30);
    }

    #[test]
    fn test_fold_subtraction() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(50)),
            b("t1", mk_int(20)),
            b("t2", bin_op("-", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 30);
    }

    #[test]
    fn test_fold_multiplication() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(6)),
            b("t1", mk_int(7)),
            b("t2", bin_op("*", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 42);
    }

    #[test]
    fn test_fold_division() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(100)),
            b("t1", mk_int(4)),
            b("t2", bin_op("/", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 25);
    }

    #[test]
    fn test_no_fold_div_by_zero() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(100)),
            b("t1", mk_int(0)),
            b("t2", bin_op("/", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "bin_op");
    }

    #[test]
    fn test_fold_modulo() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(3)),
            b("t2", bin_op("%", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 1);
    }

    #[test]
    fn test_no_fold_mod_by_zero() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(100)),
            b("t1", mk_int(0)),
            b("t2", bin_op("%", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "bin_op");
    }

    #[test]
    fn test_fold_comparisons() {
        let cases: Vec<(&str, i128, i128, bool)> = vec![
            ("===", 5, 5, true),
            ("!==", 5, 5, false),
            ("<", 5, 6, true),
            (">", 6, 5, true),
            ("<=", 5, 5, true),
            (">=", 5, 5, true),
        ];
        for (op, a, b_val, expected) in cases {
            let p = make_program(vec![make_method("m", vec![
                b("t0", mk_int(a)),
                b("t1", mk_int(b_val)),
                b("t2", bin_op(op, "t0", "t1")),
            ])]);
            let r = fold_constants_only(&p);
            assert_load_const_bool(&r.methods[0].body[2].value, expected);
        }
    }

    // -----------------------------------------------------------------------
    // 2. Shift operators
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_left_shift() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(1)),
            b("t1", mk_int(3)),
            b("t2", bin_op("<<", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 8);
    }

    #[test]
    fn test_fold_right_shift() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(16)),
            b("t1", mk_int(2)),
            b("t2", bin_op(">>", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 4);
    }

    #[test]
    fn test_no_fold_negative_shift() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(-8)),
            b("t1", mk_int(1)),
            b("t2", bin_op(">>", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "bin_op");
    }

    // -----------------------------------------------------------------------
    // 3. Bitwise operators
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_bitwise() {
        // AND: 0b1100 & 0b1010 = 0b1000 = 8
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(0b1100)),
            b("t1", mk_int(0b1010)),
            b("t2", bin_op("&", "t0", "t1")),
            b("t3", bin_op("|", "t0", "t1")),
            b("t4", bin_op("^", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 8);
        assert_load_const_int(&r.methods[0].body[3].value, 14);
        assert_load_const_int(&r.methods[0].body[4].value, 6);
    }

    // -----------------------------------------------------------------------
    // 4. Boolean operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_boolean_and_or() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(true)),
            b("t1", mk_bool(false)),
            b("t2", bin_op("&&", "t0", "t1")),
            b("t3", bin_op("||", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[2].value, false);
        assert_load_const_bool(&r.methods[0].body[3].value, true);
    }

    #[test]
    fn test_fold_boolean_equality() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(true)),
            b("t1", mk_bool(true)),
            b("t2", bin_op("===", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[2].value, true);
    }

    // -----------------------------------------------------------------------
    // 5. String (ByteString) operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_hex_concat() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_str("ab")),
            b("t1", mk_str("cd")),
            b("t2", bin_op("+", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_str(&r.methods[0].body[2].value, "abcd");
    }

    #[test]
    fn test_no_fold_invalid_hex_concat() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_str("aabb")),
            b("t1", mk_str("zzzz")),
            b("t2", bin_op("+", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "bin_op");
    }

    #[test]
    fn test_fold_string_equality() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_str("abc")),
            b("t1", mk_str("abc")),
            b("t2", bin_op("===", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[2].value, true);
    }

    // -----------------------------------------------------------------------
    // 6. Unary operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_boolean_negation() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(true)),
            b("t1", unary_op("!", "t0")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[1].value, false);
    }

    #[test]
    fn test_fold_int_negation() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(42)),
            b("t1", unary_op("-", "t0")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, -42);
    }

    #[test]
    fn test_fold_bitwise_not() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(0)),
            b("t1", unary_op("~", "t0")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, -1);
    }

    #[test]
    fn test_fold_bang_on_zero() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(0)),
            b("t1", unary_op("!", "t0")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[1].value, true);
    }

    // -----------------------------------------------------------------------
    // 7. Constant propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_propagation_chain() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(20)),
            b("t2", bin_op("+", "t0", "t1")),
            b("t3", mk_int(12)),
            b("t4", bin_op("+", "t2", "t3")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[4].value, 42);
    }

    #[test]
    fn test_no_fold_with_param() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", load_param("x")),
            b("t1", mk_int(5)),
            b("t2", bin_op("+", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "bin_op");
    }

    // -----------------------------------------------------------------------
    // 8. If-branch folding
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_true_branch() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(true)),
            b("t1", ANFValue::If {
                cond: "t0".to_string(),
                then: vec![b("t2", mk_int(42))],
                else_branch: vec![b("t3", mk_int(99))],
            }),
        ])]);
        let r = fold_constants_only(&p);
        if let ANFValue::If { then, else_branch, .. } = &r.methods[0].body[1].value {
            assert_eq!(then.len(), 1);
            assert_eq!(else_branch.len(), 0);
        } else {
            panic!("expected If");
        }
    }

    #[test]
    fn test_fold_false_branch() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(false)),
            b("t1", ANFValue::If {
                cond: "t0".to_string(),
                then: vec![b("t2", mk_int(42))],
                else_branch: vec![b("t3", mk_int(99))],
            }),
        ])]);
        let r = fold_constants_only(&p);
        if let ANFValue::If { then, else_branch, .. } = &r.methods[0].body[1].value {
            assert_eq!(then.len(), 0);
            assert_eq!(else_branch.len(), 1);
        } else {
            panic!("expected If");
        }
    }

    #[test]
    fn test_fold_constants_in_branches() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", load_param("flag")),
            b("t1", mk_int(5)),
            b("t2", mk_int(3)),
            b("t3", ANFValue::If {
                cond: "t0".to_string(),
                then: vec![b("t4", bin_op("+", "t1", "t2"))],
                else_branch: vec![b("t5", bin_op("-", "t1", "t2"))],
            }),
        ])]);
        let r = fold_constants_only(&p);
        if let ANFValue::If { then, else_branch, .. } = &r.methods[0].body[3].value {
            assert_load_const_int(&then[0].value, 8);
            assert_load_const_int(&else_branch[0].value, 2);
        } else {
            panic!("expected If");
        }
    }

    // -----------------------------------------------------------------------
    // 9. Loop folding
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_constants_in_loop() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(20)),
            b("t2", ANFValue::Loop {
                count: 5,
                body: vec![b("t3", bin_op("+", "t0", "t1"))],
                iter_var: "i".to_string(),
            }),
        ])]);
        let r = fold_constants_only(&p);
        if let ANFValue::Loop { body, .. } = &r.methods[0].body[2].value {
            assert_load_const_int(&body[0].value, 30);
        } else {
            panic!("expected Loop");
        }
    }

    // -----------------------------------------------------------------------
    // 10. Non-foldable values pass through
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_param_unchanged() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", load_param("x")),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[0].value, "load_param");
    }

    #[test]
    fn test_load_prop_unchanged() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", ANFValue::LoadProp { name: "pk".to_string() }),
        ])]);
        let r = fold_constants_only(&p);
        match &r.methods[0].body[0].value {
            ANFValue::LoadProp { .. } => {}
            _ => panic!("expected LoadProp"),
        }
    }

    #[test]
    fn test_assert_unchanged() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_bool(true)),
            b("t1", ANFValue::Assert { value: "t0".to_string() }),
        ])]);
        let r = fold_constants_only(&p);
        match &r.methods[0].body[1].value {
            ANFValue::Assert { .. } => {}
            _ => panic!("expected Assert"),
        }
    }

    // -----------------------------------------------------------------------
    // 11. Pure math builtin folding
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_abs() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(-5)),
            b("t1", call_func("abs", vec!["t0"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, 5);
    }

    #[test]
    fn test_fold_min() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(3)),
            b("t1", mk_int(7)),
            b("t2", call_func("min", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 3);
    }

    #[test]
    fn test_fold_max() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(3)),
            b("t1", mk_int(7)),
            b("t2", call_func("max", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 7);
    }

    #[test]
    fn test_fold_safediv() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(3)),
            b("t2", call_func("safediv", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 3);
    }

    #[test]
    fn test_no_fold_safediv_by_zero() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(0)),
            b("t2", call_func("safediv", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_not_folded(&r.methods[0].body[2].value, "call");
    }

    #[test]
    fn test_fold_safemod() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(3)),
            b("t2", call_func("safemod", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 1);
    }

    #[test]
    fn test_fold_clamp() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(15)),
            b("t1", mk_int(0)),
            b("t2", mk_int(10)),
            b("t3", call_func("clamp", vec!["t0", "t1", "t2"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[3].value, 10);
    }

    #[test]
    fn test_fold_sign() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(-42)),
            b("t1", call_func("sign", vec!["t0"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, -1);
    }

    #[test]
    fn test_fold_pow() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(2)),
            b("t1", mk_int(10)),
            b("t2", call_func("pow", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 1024);
    }

    #[test]
    fn test_fold_muldiv() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(10)),
            b("t1", mk_int(20)),
            b("t2", mk_int(3)),
            b("t3", call_func("mulDiv", vec!["t0", "t1", "t2"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[3].value, 66);
    }

    #[test]
    fn test_fold_percent_of() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(1000)),
            b("t1", mk_int(500)),
            b("t2", call_func("percentOf", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 50);
    }

    #[test]
    fn test_fold_sqrt() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(144)),
            b("t1", call_func("sqrt", vec!["t0"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, 12);
    }

    #[test]
    fn test_fold_gcd() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(12)),
            b("t1", mk_int(8)),
            b("t2", call_func("gcd", vec!["t0", "t1"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[2].value, 4);
    }

    #[test]
    fn test_fold_log2() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(256)),
            b("t1", call_func("log2", vec!["t0"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_int(&r.methods[0].body[1].value, 8);
    }

    #[test]
    fn test_fold_bool_builtin() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(0)),
            b("t1", call_func("bool", vec!["t0"])),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[1].value, false);
    }

    // -----------------------------------------------------------------------
    // 12. Cross-type equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_cross_type_equality() {
        let p = make_program(vec![make_method("m", vec![
            b("t0", mk_int(1)),
            b("t1", mk_bool(true)),
            b("t2", bin_op("===", "t0", "t1")),
            b("t3", bin_op("!==", "t0", "t1")),
        ])]);
        let r = fold_constants_only(&p);
        assert_load_const_bool(&r.methods[0].body[2].value, false);
        assert_load_const_bool(&r.methods[0].body[3].value, true);
    }
}
