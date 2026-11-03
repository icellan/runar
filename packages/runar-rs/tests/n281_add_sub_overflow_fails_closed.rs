//! N-281: the SDK ANF interpreter's `+` / `-` bin_ops used `wrapping_add` /
//! `wrapping_sub`, and unary `-` / the `abs` builtin used plain `i64`
//! arithmetic — all four silently WRAP (or, for `abs`/unary `-` in a
//! debug/overflow-checked build, panic) on i64::MIN / i64::MAX edges instead
//! of refusing. On a node the compiled script computes the exact bigint
//! result (OP_ADD/OP_SUB/OP_NEGATE operate on Bitcoin Script's unbounded
//! script-number encoding, not a fixed-width machine integer), so the
//! interpreter's wrapped i64 silently diverges from the on-chain post-state.
//! `*` was already fixed this way under N-163 (`checked_mul`); this item is
//! its `+` / `-` / `abs` / unary `-` sibling.
//!
//! Proves: `bin_op +`, `bin_op -`, `unary_op -`, and `call abs` all refuse
//! (return `Err`, never wrap to a bogus i64) at the exact i64 edges
//! `i64::MAX + 1`, `i64::MIN - 1`, `-i64::MIN`, and `abs(i64::MIN)` — and
//! still compute the correct in-range value either side of each edge.
//! Does not prove: `*` overflow (covered by N-163) or anything about the
//! compiled script itself (this is the off-chain post-state predictor, not
//! the on-chain oracle).

use std::collections::HashMap;

use runar_lang::sdk::anf_interpreter::{compute_new_state, ANFProgram};
use runar_lang::sdk::SdkValue;

fn bin_op_anf(op: &str) -> ANFProgram {
    serde_json::from_value(serde_json::json!({
        "contractName": "AddSubProbe",
        "properties": [{"name": "result", "type": "bigint", "readonly": false}],
        "methods": [{"name": "probe", "params": [
            {"name": "a", "type": "bigint"}, {"name": "b", "type": "bigint"}
        ], "body": [
            {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
            {"name": "t1", "value": {"kind": "load_param", "name": "b"}},
            {"name": "r", "value": {"kind": "bin_op", "op": op, "left": "t0", "right": "t1"}},
            {"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}}
        ], "isPublic": true}],
    }))
    .expect("bin_op ANF")
}

fn run_bin_op(op: &str, a: i64, b: i64) -> Result<HashMap<String, SdkValue>, String> {
    let anf = bin_op_anf(op);
    let mut named = HashMap::new();
    named.insert("a".to_string(), SdkValue::Int(a));
    named.insert("b".to_string(), SdkValue::Int(b));
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    compute_new_state(&anf, "probe", &state, &named, &[])
}

fn unary_or_call_anf(kind_json: serde_json::Value) -> ANFProgram {
    serde_json::from_value(serde_json::json!({
        "contractName": "UnaryAbsProbe",
        "properties": [{"name": "result", "type": "bigint", "readonly": false}],
        "methods": [{"name": "probe", "params": [
            {"name": "a", "type": "bigint"}
        ], "body": [
            {"name": "t0", "value": {"kind": "load_param", "name": "a"}},
            {"name": "r", "value": kind_json},
            {"name": "u", "value": {"kind": "update_prop", "name": "result", "value": "r"}}
        ], "isPublic": true}],
    }))
    .expect("unary/call ANF")
}

fn run_negate(a: i64) -> Result<HashMap<String, SdkValue>, String> {
    let anf = unary_or_call_anf(serde_json::json!({"kind": "unary_op", "op": "-", "operand": "t0"}));
    let mut named = HashMap::new();
    named.insert("a".to_string(), SdkValue::Int(a));
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    compute_new_state(&anf, "probe", &state, &named, &[])
}

fn run_abs(a: i64) -> Result<HashMap<String, SdkValue>, String> {
    let anf = unary_or_call_anf(serde_json::json!({"kind": "call", "func": "abs", "args": ["t0"]}));
    let mut named = HashMap::new();
    named.insert("a".to_string(), SdkValue::Int(a));
    let mut state = HashMap::new();
    state.insert("result".to_string(), SdkValue::Int(0));
    compute_new_state(&anf, "probe", &state, &named, &[])
}

/// `a + b` past i64::MAX must be refused, not wrapped (`wrapping_add`).
#[test]
fn n281_anf_interpreter_add_overflow_fails_closed() {
    assert!(matches!(run_bin_op("+", 6, 7).unwrap().get("result"), Some(SdkValue::Int(13))));
    let got = run_bin_op("+", i64::MAX, 1);
    assert!(got.is_err(), "i64::MAX + 1 must be refused, got {:?}", got);
}

/// `a - b` past i64::MIN must be refused, not wrapped (`wrapping_sub`).
#[test]
fn n281_anf_interpreter_sub_overflow_fails_closed() {
    assert!(matches!(run_bin_op("-", 6, 7).unwrap().get("result"), Some(SdkValue::Int(-1))));
    let got = run_bin_op("-", i64::MIN, 1);
    assert!(got.is_err(), "i64::MIN - 1 must be refused, got {:?}", got);
}

/// Unary `-` on `i64::MIN` (`-i64::MIN` == `i64::MAX + 1`) must be refused.
#[test]
fn n281_anf_interpreter_unary_negate_overflow_fails_closed() {
    assert!(matches!(run_negate(6).unwrap().get("result"), Some(SdkValue::Int(-6))));
    let got = run_negate(i64::MIN);
    assert!(got.is_err(), "-i64::MIN must be refused, got {:?}", got);
}

/// `abs(i64::MIN)` (== `i64::MAX + 1`) must be refused.
#[test]
fn n281_anf_interpreter_abs_overflow_fails_closed() {
    assert!(matches!(run_abs(-6).unwrap().get("result"), Some(SdkValue::Int(6))));
    let got = run_abs(i64::MIN);
    assert!(got.is_err(), "abs(i64::MIN) must be refused, got {:?}", got);
}
