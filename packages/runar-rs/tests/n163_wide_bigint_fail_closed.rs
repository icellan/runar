//! N-163 (design B, refuse on use): the SDK ANF interpreter's integer is i64.
//! A caller-supplied `SdkValue::BigInt` outside i64 used to be read as 0
//! (`unwrap_or(0)`), so arithmetic on it derived a post-state the script never
//! produces. It is now carried unchanged and refused only where the
//! interpreter would have to compute with it.
//!
//! Proves: (i) a stateful method that carries wide values without computing
//! with them (the BlackjackBet shape: a wide `RabinPubKey` property and a wide
//! `RabinSig` param fed only to `verifyRabinSig`) still derives its post-state,
//! and a wide value assigned to state comes back as the exact `BigInt`;
//! (ii) a wide value used as a `bin_op` / `unary_op` operand, a builtin
//! argument, or an output's satoshis is refused with an "outside the i64
//! range" error — never computed as 0.
//! Does not prove: arithmetic on wide values (the interpreter refuses it; the
//! on-chain script computes it), wide literals inside the ANF itself
//! (`load_const`), or anything about the compiled script.

use std::collections::HashMap;

use num_bigint::BigInt;
use runar_lang::sdk::anf_interpreter::{compute_new_state, compute_new_state_and_data_outputs, ANFProgram};
use runar_lang::sdk::SdkValue;

/// A value outside i64: 2^bits + 12345.
fn wide(bits: u32) -> BigInt {
    (BigInt::from(1) << bits) + 12345
}

fn program(params: serde_json::Value, body: serde_json::Value) -> ANFProgram {
    serde_json::from_value(serde_json::json!({
        "contractName": "WideProbe",
        "properties": [
            {"name": "oraclePubKey", "type": "RabinPubKey", "readonly": true},
            {"name": "count", "type": "bigint", "readonly": false},
            {"name": "lastSig", "type": "RabinSig", "readonly": false}
        ],
        "methods": [{"name": "settle", "params": params, "body": body, "isPublic": true}],
    }))
    .expect("probe ANF")
}

fn state() -> HashMap<String, SdkValue> {
    let mut s = HashMap::new();
    s.insert("count".to_string(), SdkValue::Int(0));
    s.insert("lastSig".to_string(), SdkValue::Int(0));
    s
}

fn ctor() -> Vec<SdkValue> {
    vec![SdkValue::BigInt(wide(300)), SdkValue::Int(0), SdkValue::Int(0)]
}

/// The BlackjackBet shape (examples/end2end-example/webapp-blackjack): a
/// wide `RabinPubKey` property and a wide `RabinSig` param reach only
/// `verifyRabinSig`, and the method bumps `count`. Must keep deriving state.
fn blackjack_shape(extra: serde_json::Value) -> Result<HashMap<String, SdkValue>, String> {
    let mut body = vec![
        serde_json::json!({"name": "m", "value": {"kind": "load_const", "value": "aa"}}),
        serde_json::json!({"name": "s", "value": {"kind": "load_param", "name": "rabinSig"}}),
        serde_json::json!({"name": "p", "value": {"kind": "load_param", "name": "padding"}}),
        serde_json::json!({"name": "k", "value": {"kind": "load_prop", "name": "oraclePubKey"}}),
        serde_json::json!({"name": "v", "value": {"kind": "call", "func": "verifyRabinSig", "args": ["m", "s", "p", "k"]}}),
        serde_json::json!({"name": "a", "value": {"kind": "assert", "value": "v"}}),
        serde_json::json!({"name": "c", "value": {"kind": "load_prop", "name": "count"}}),
        serde_json::json!({"name": "one", "value": {"kind": "load_const", "value": 1}}),
        serde_json::json!({"name": "n", "value": {"kind": "bin_op", "op": "+", "left": "c", "right": "one"}}),
        serde_json::json!({"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}),
    ];
    body.extend(extra.as_array().unwrap().iter().cloned());
    let anf = program(
        serde_json::json!([{"name": "rabinSig", "type": "RabinSig"}, {"name": "padding", "type": "ByteString"}]),
        serde_json::Value::Array(body),
    );
    let mut args = HashMap::new();
    args.insert("rabinSig".to_string(), SdkValue::BigInt(wide(260)));
    args.insert("padding".to_string(), SdkValue::Bytes("00".into()));
    compute_new_state(&anf, "settle", &state(), &args, &ctor())
}

#[test]
fn n163_wide_values_carried_without_arithmetic_still_derive_state() {
    let out = blackjack_shape(serde_json::json!([])).expect("derives state");
    assert!(matches!(out.get("count"), Some(SdkValue::Int(1))), "count: {:?}", out.get("count"));
}

#[test]
fn n163_wide_value_assigned_to_state_round_trips_exactly() {
    let out = blackjack_shape(serde_json::json!([
        {"name": "u2", "value": {"kind": "update_prop", "name": "lastSig", "value": "s"}}
    ]))
    .expect("derives state");
    match out.get("lastSig") {
        Some(SdkValue::BigInt(n)) => assert_eq!(*n, wide(260)),
        other => panic!("wide value must reach state unchanged, got {:?}", other),
    }
}

/// Run `body` with a wide `w` param (and the wide ctor prop) and return the
/// interpreter's answer.
fn run_with_wide_param(body: serde_json::Value) -> Result<HashMap<String, SdkValue>, String> {
    let anf = program(serde_json::json!([{"name": "w", "type": "bigint"}]), body);
    let mut args = HashMap::new();
    args.insert("w".to_string(), SdkValue::BigInt(wide(100)));
    compute_new_state_and_data_outputs(&anf, "settle", &state(), &args, &ctor()).map(|(s, _, _, _)| s)
}

fn assert_refused(what: &str, got: Result<HashMap<String, SdkValue>, String>) {
    match got {
        Err(e) => assert!(e.contains("outside the i64 range"), "{}: wrong refusal: {}", what, e),
        Ok(s) => panic!("{}: a wide operand must be refused, got state {:?}", what, s),
    }
}

#[test]
fn n163_wide_value_used_in_arithmetic_is_refused() {
    let load = serde_json::json!([
        {"name": "w0", "value": {"kind": "load_param", "name": "w"}},
        {"name": "c", "value": {"kind": "load_prop", "name": "count"}}
    ]);
    let with = |tail: serde_json::Value| {
        let mut b = load.as_array().unwrap().clone();
        b.extend(tail.as_array().unwrap().iter().cloned());
        serde_json::Value::Array(b)
    };
    assert_refused("bin_op +", run_with_wide_param(with(serde_json::json!([
        {"name": "n", "value": {"kind": "bin_op", "op": "+", "left": "c", "right": "w0"}},
        {"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}
    ]))));
    assert_refused("bin_op > (readonly prop)", run_with_wide_param(with(serde_json::json!([
        {"name": "k", "value": {"kind": "load_prop", "name": "oraclePubKey"}},
        {"name": "n", "value": {"kind": "bin_op", "op": ">", "left": "k", "right": "c"}},
        {"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}
    ]))));
    assert_refused("unary_op -", run_with_wide_param(with(serde_json::json!([
        {"name": "n", "value": {"kind": "unary_op", "op": "-", "operand": "w0"}},
        {"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}
    ]))));
    assert_refused("builtin abs", run_with_wide_param(with(serde_json::json!([
        {"name": "n", "value": {"kind": "call", "func": "abs", "args": ["w0"]}},
        {"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}
    ]))));
    assert_refused("add_data_output satoshis", run_with_wide_param(with(serde_json::json!([
        {"name": "sc", "value": {"kind": "load_const", "value": "6a"}},
        {"name": "o", "value": {"kind": "add_data_output", "satoshis": "w0", "scriptBytes": "sc"}}
    ]))));
}
