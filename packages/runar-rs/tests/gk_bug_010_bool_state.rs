//! GK-BUG-010: a boolean state field accepts only `SdkValue::Bool`.
//!
//! Every tier used to encode a NON-boolean by its own rule (Ruby/TS/Python
//! truthiness, Go/Java "anything but true is 00", Zig `.int != 0`); this tier
//! reached `as_bool`'s unnamed panic. Now every tier refuses a non-boolean
//! with a named error, as the num2bin arm (N-084) refuses a non-integer.
//!
//! Proves: `serialize_state` panics naming the field and type for Int, BigInt,
//! Bytes ("true" / "01" / ""), Auto, EmptySig and Array in both spellings of
//! the type, and Bool(true) / Bool(false) keep 01 / 00. Does not prove anything
//! on chain, nor the other six SDKs.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

use runar_lang::sdk::state::serialize_state;
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

const TYPES: &[&str] = &["bool", "boolean"];

fn field(t: &str) -> Vec<StateField> {
    vec![StateField { name: "flag".into(), field_type: t.into(), index: 0, initial_value: None, fixed_array: None }]
}

fn run(t: &str, v: SdkValue) -> Result<String, String> {
    let mut m = HashMap::new();
    m.insert("flag".to_string(), v);
    catch_unwind(AssertUnwindSafe(|| serialize_state(&field(t), &m))).map_err(|e| {
        e.downcast_ref::<String>().cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    })
}

#[test]
fn refuses_non_bool() {
    let bad = vec![
        ("int 0", SdkValue::Int(0)),
        ("int 1", SdkValue::Int(1)),
        ("bigint 1", SdkValue::BigInt(num_bigint::BigInt::from(1))),
        ("bytes true", SdkValue::Bytes("true".into())),
        ("bytes 01", SdkValue::Bytes("01".into())),
        ("bytes empty", SdkValue::Bytes(String::new())),
        ("auto", SdkValue::Auto),
        ("empty sig", SdkValue::EmptySig),
        ("array", SdkValue::Array(vec![SdkValue::Bool(true)])),
    ];
    for t in TYPES {
        for (name, v) in &bad {
            let want = format!("state field \"flag\" ({}) must be a boolean", t);
            match run(t, v.clone()) {
                Err(msg) if msg.contains(&want) => {}
                other => panic!("{}/{}: want panic containing {:?}, got {:?}", t, name, want, other),
            }
        }
    }
}

#[test]
fn true_false_unchanged() {
    for t in TYPES {
        assert_eq!(run(t, SdkValue::Bool(true)).as_deref(), Ok("01"), "{t}");
        assert_eq!(run(t, SdkValue::Bool(false)).as_deref(), Ok("00"), "{t}");
    }
}
