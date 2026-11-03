//! N-282: a beyond-i64 ANF `load_const` literal (`"<digits>n"`) reached
//! `json_to_val`, and because `stripped.parse::<i64>()` overflows, fell
//! through to the `Val::Bytes` branch -- so `to_i64()` read it as 0 and
//! arithmetic on the literal silently derived a post-state the on-chain
//! script never produces (same class as N-163, different entry point: N-163
//! covers a caller-supplied `SdkValue::BigInt` reaching `Val::from_sdk`; this
//! item covers the same value arriving as an ANF literal through
//! `json_to_val`/`load_const`).
//!
//! Proves: a stateful method whose body contains a `load_const` of a
//! beyond-i64 bigint literal, used as a `bin_op` operand, is refused with
//! the "outside the i64 range" error -- never silently computed as 0.
//! Does not prove: arithmetic on wide values (the interpreter refuses it;
//! the on-chain script computes it), or anything about the compiled script.

use std::collections::HashMap;

use runar_lang::sdk::anf_interpreter::compute_new_state;
use runar_lang::sdk::SdkValue;

/// 2^70 + 12345, outside i64 (max i64 is ~9.2e18).
const WIDE_LITERAL: &str = "1180591620717411315769n";

fn anf_with_wide_const_in_arithmetic() -> serde_json::Value {
    serde_json::json!({
        "contractName": "WideLiteralProbe",
        "properties": [
            {"name": "count", "type": "bigint", "readonly": false}
        ],
        "methods": [{
            "name": "settle",
            "params": [],
            "isPublic": true,
            "body": [
                {"name": "c", "value": {"kind": "load_prop", "name": "count"}},
                {"name": "w", "value": {"kind": "load_const", "value": WIDE_LITERAL}},
                {"name": "n", "value": {"kind": "bin_op", "op": "+", "left": "c", "right": "w"}},
                {"name": "u", "value": {"kind": "update_prop", "name": "count", "value": "n"}}
            ]
        }]
    })
}

#[test]
fn n282_wide_load_const_literal_used_in_arithmetic_is_refused() {
    let anf = serde_json::from_value(anf_with_wide_const_in_arithmetic()).expect("probe ANF");
    let mut state = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(5));

    let result = compute_new_state(&anf, "settle", &state, &HashMap::new(), &[]);
    match result {
        Err(e) => assert!(e.contains("outside the i64 range"), "wrong refusal: {}", e),
        Ok(s) => panic!(
            "a beyond-i64 load_const literal used in arithmetic must be refused, got state {:?}",
            s
        ),
    }
}
