//! A mutable `boolean` state field is ONE raw byte — `01` or `00`.
//!
//! The compiler spells the type `boolean`. `bool` appears nowhere in any of the
//! seven frontends, so an artifact's `stateFields` never carries it; the SDKs
//! that matched on `"bool"` alone were matching a spelling no compiler emits,
//! and every real boolean field fell through to their push-data default:
//!
//! ```text
//! typescript  01           correct
//! ruby        01           correct
//! go          02 74727565  push-framed ASCII "true" — 3 bytes too long
//! java        02 74727565  same
//! python      00           right width, ALWAYS false
//! zig         00           same
//! rust        panic        as_bytes() on a Bool variant
//! ```
//!
//! All five are fund-affecting. Go and Java deploy a state tail longer than the
//! one the script's own reader rebuilds, so `hash256(outputs)` can never match
//! and the first spend is impossible. Python and Zig deploy a well-formed tail
//! that says `false` whatever the caller passed, so the first call that sets the
//! flag builds a continuation the covenant rejects. Rust fails closed — this
//! tier PANICKED rather than write wrong bytes, which is the least bad of the
//! three failure modes and still a broken deploy path.
//!
//! `cross_sdk_golden` is byte-identical across all seven SDKs; every tier
//! carries the same literal and the same field list. The trailing `bigint` is
//! load-bearing: a boolean of the wrong WIDTH shifts it, so the record catches a
//! length error that a lone boolean field would hide.

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, serialize_state};
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

fn field(name: &str, field_type: &str, index: usize) -> StateField {
    StateField {
        name: name.to_string(),
        field_type: field_type.to_string(),
        index,
        initial_value: None,
        fixed_array: None,
    }
}

fn boolean_spelling_fields() -> Vec<StateField> {
    vec![
        field("count", "bigint", 0),
        // The canonical spelling — the only one any compiler emits.
        field("flag", "boolean", 1),
        // The alias. Several tiers accepted only this one; it must keep working.
        field("alias", "bool", 2),
        field("tail", "bigint", 3),
    ]
}

fn values(flag: bool, alias: bool) -> HashMap<String, SdkValue> {
    let mut v: HashMap<String, SdkValue> = HashMap::new();
    v.insert("count".into(), SdkValue::Int(7));
    v.insert("flag".into(), SdkValue::Bool(flag));
    v.insert("alias".into(), SdkValue::Bool(alias));
    v.insert("tail".into(), SdkValue::Int(1));
    v
}

/// The one wire record every tier must reproduce byte for byte.
fn cross_sdk_golden() -> String {
    [
        "0700000000000000", // bigint 7, NUM2BIN 8
        "01",               // boolean true  — 1 raw byte
        "00",               // bool    false — 1 raw byte
        "0100000000000000", // bigint 1, NUM2BIN 8
    ]
    .concat()
}

fn flipped_golden() -> String {
    ["0700000000000000", "00", "01", "0100000000000000"].concat()
}

fn bool_of(v: &SdkValue) -> bool {
    match v {
        SdkValue::Bool(b) => *b,
        other => panic!("expected SdkValue::Bool, got {other:?}"),
    }
}

fn int_of(v: &SdkValue) -> i64 {
    match v {
        SdkValue::Int(n) => *n,
        other => panic!("expected SdkValue::Int, got {other:?}"),
    }
}

#[test]
fn boolean_spelling_cross_sdk_golden_serialize() {
    let want = cross_sdk_golden();
    assert_eq!(want.len() / 2, 18);
    assert_eq!(serialize_state(&boolean_spelling_fields(), &values(true, false)), want);
}

#[test]
fn boolean_spelling_opposite_polarity() {
    assert_eq!(
        serialize_state(&boolean_spelling_fields(), &values(false, true)),
        flipped_golden()
    );
}

#[test]
fn boolean_spelling_cross_sdk_golden_deserialize() {
    let back = deserialize_state(&boolean_spelling_fields(), &cross_sdk_golden());
    assert_eq!(int_of(&back["count"]), 7);
    assert!(bool_of(&back["flag"]));
    assert!(!bool_of(&back["alias"]));
    assert_eq!(int_of(&back["tail"]), 1);
}

#[test]
fn boolean_spelling_flipped_deserialize() {
    let back = deserialize_state(&boolean_spelling_fields(), &flipped_golden());
    assert!(!bool_of(&back["flag"]));
    assert!(bool_of(&back["alias"]));
}

#[test]
fn boolean_spelling_lone_field_is_one_byte() {
    let fields = vec![field("v", "boolean", 0)];
    for (value, want) in [(true, "01"), (false, "00")] {
        let mut v: HashMap<String, SdkValue> = HashMap::new();
        v.insert("v".into(), SdkValue::Bool(value));
        assert_eq!(serialize_state(&fields, &v), want);
        assert_eq!(bool_of(&deserialize_state(&fields, want)["v"]), value);
    }
}
