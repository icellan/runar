//! N-084: the num2bin state encode path fails closed.
//!
//! `state_field_i64` returned 0 for a `SdkValue::Bytes` that was not a decimal
//! integer string (a hex string, "", "abc"), and reached `as_int` for the
//! other variants, which panicked with an unnamed message. Both must now be a
//! named refusal.
//!
//! Proves: `serialize_state` panics naming the field and type for Bytes
//! (hex / empty / non-decimal), Bool, Auto, EmptySig and Array in each of the
//! four num2bin types; valid integers and decimal integer strings keep their
//! exact bytes. Does not prove anything on chain, nor the other six SDKs.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use runar_lang::sdk::state::serialize_state;
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

const TYPES: &[&str] = &["int", "bigint", "RabinSig", "RabinPubKey"];

fn field(t: &str) -> Vec<StateField> {
    vec![StateField { name: "k".into(), field_type: t.into(), index: 0, initial_value: None, fixed_array: None }]
}

fn run(t: &str, v: SdkValue) -> Result<String, String> {
    let mut m = HashMap::new();
    m.insert("k".to_string(), v);
    catch_unwind(AssertUnwindSafe(|| serialize_state(&field(t), &m))).map_err(|e| {
        e.downcast_ref::<String>().cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

#[test]
fn refuses_non_integer() {
    let bad = vec![
        ("hex digits", SdkValue::Bytes("deadbeef".into())),
        ("empty", SdkValue::Bytes(String::new())),
        ("0x hex", SdkValue::Bytes("0x10".into())),
        ("non-decimal", SdkValue::Bytes("abc".into())),
        ("bool", SdkValue::Bool(true)),
        ("auto", SdkValue::Auto),
        ("empty sig", SdkValue::EmptySig),
        ("array", SdkValue::Array(vec![SdkValue::Int(1)])),
    ];
    for t in TYPES {
        for (name, v) in &bad {
            let want = format!("state field \"k\" ({}) must be an integer", t);
            match run(t, v.clone()) {
                Err(msg) if msg.contains(&want) => {}
                other => panic!("{}/{}: want panic containing {:?}, got {:?}", t, name, want, other),
            }
        }
    }
}

#[test]
fn valid_integers_unchanged() {
    let cases = vec![
        (SdkValue::Int(0), "0000000000000000"),
        (SdkValue::Int(5), "0500000000000000"),
        (SdkValue::Int(-5), "0500000000000080"),
        (SdkValue::BigInt(num_bigint::BigInt::from(-5)), "0500000000000080"),
        (SdkValue::Bytes("5".into()), "0500000000000000"),
        (SdkValue::Bytes("5n".into()), "0500000000000000"),
        (SdkValue::Bytes("-5n".into()), "0500000000000080"),
    ];
    for t in TYPES {
        for (v, want) in &cases {
            assert_eq!(run(t, v.clone()).as_deref(), Ok(*want), "{} {:?}", t, v);
        }
    }
}
