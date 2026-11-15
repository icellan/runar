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

// The refusal above must not reject a boolean the SDK computed itself. The
// language declares `bool(x): boolean`, but the ANF interpreter returned
// `Val::Int(1)` / `Val::Int(0)`, so a contract doing
// `this.flag = bool(this.count)` produced a post-state the serializer
// refuses (before GK-BUG-010, through as_bool's unnamed panic).
#[test]
fn interpreter_computed_bool_serializes() {
    let anf = serde_json::from_value(serde_json::json!({
        "contractName": "BoolProbe",
        "properties": [
            {"name": "count", "type": "bigint", "readonly": false},
            {"name": "flag", "type": "bool", "readonly": false}
        ],
        "methods": [{
            "name": "step", "params": [], "isPublic": true,
            "body": [
                {"name": "c", "value": {"kind": "load_prop", "name": "count"}},
                {"name": "b", "value": {"kind": "call", "func": "bool", "args": ["c"]}},
                {"name": "u", "value": {"kind": "update_prop", "name": "flag", "value": "b"}}
            ]
        }]
    }))
    .expect("probe ANF");
    for (count, want) in [(5i64, "01"), (0i64, "00")] {
        let mut state = HashMap::new();
        state.insert("count".to_string(), SdkValue::Int(count));
        state.insert("flag".to_string(), SdkValue::Bool(count == 0));
        let st = runar_lang::sdk::anf_interpreter::compute_new_state(&anf, "step", &state, &HashMap::new(), &[])
            .expect("compute_new_state");
        let flag = st.get("flag").cloned().expect("flag in post-state");
        assert!(matches!(flag, SdkValue::Bool(_)), "count={}: bool() gave {:?}, want SdkValue::Bool", count, flag);
        assert_eq!(run("bool", flag), Ok(want.to_string()), "count={}", count);
    }
}
