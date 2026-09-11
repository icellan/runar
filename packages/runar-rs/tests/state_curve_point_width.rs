//! `P256Point` (64) and `P384Point` (96) are FIXED-WIDTH RAW state fields.
//!
//! All seven compilers emit them as fixed raw slices in the state tail, and
//! `runar-lang`'s cast constructors hard-assert exactly those widths. The seven
//! SDKs used to omit both from their width tables, so they fell through to the
//! push-data default and deployed a state section 1 byte (`0x40` direct push)
//! or 2 bytes (`OP_PUSHDATA1 0x60`) longer than the script's own on-chain
//! reader expects. The deploy succeeded and the FIRST spend failed with
//! `OP_NUMEQUALVERIFY requires the top stack item to be truthy` — funds locked.
//!
//! `cross_sdk_golden` is byte-identical across all seven SDKs; every tier
//! carries the same literal and the same field list.

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, serialize_state};
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

fn rep(s: &str, n: usize) -> String {
    s.repeat(n)
}

fn field(name: &str, field_type: &str, index: usize) -> StateField {
    StateField {
        name: name.to_string(),
        field_type: field_type.to_string(),
        index,
        initial_value: None,
        fixed_array: None,
    }
}

fn curve_point_fields() -> Vec<StateField> {
    vec![
        field("n", "bigint", 0),
        field("flag", "bool", 1),
        field("pk", "PubKey", 2),
        field("h", "Sha256", 3),
        field("ad", "Addr", 4),
        field("pt", "Point", 5),
        field("p256", "P256Point", 6),
        field("p384", "P384Point", 7),
        field("sig", "Sig", 8),
        field("rab", "RabinSig", 9),
        field("bs", "ByteString", 10),
    ]
}

fn curve_point_values() -> HashMap<String, SdkValue> {
    let mut v: HashMap<String, SdkValue> = HashMap::new();
    v.insert("n".into(), SdkValue::Int(1));
    v.insert("flag".into(), SdkValue::Bool(true));
    v.insert("pk".into(), SdkValue::Bytes(format!("02{}", rep("aa", 32))));
    v.insert("h".into(), SdkValue::Bytes(rep("bb", 32)));
    v.insert("ad".into(), SdkValue::Bytes(rep("cc", 20)));
    v.insert("pt".into(), SdkValue::Bytes(rep("dd", 64)));
    v.insert("p256".into(), SdkValue::Bytes(rep("11", 64)));
    v.insert("p384".into(), SdkValue::Bytes(rep("22", 96)));
    v.insert("sig".into(), SdkValue::Bytes(format!("3044{}", rep("ee", 66))));
    v.insert("rab".into(), SdkValue::Bytes(rep("ff", 8)));
    v.insert("bs".into(), SdkValue::Bytes("0011".into()));
    v
}

/// The one wire record every tier must reproduce byte for byte.
fn cross_sdk_golden() -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        "0100000000000000",              // bigint 1, NUM2BIN 8
        "01",                            // bool true
        format!("02{}", rep("aa", 32)),  // PubKey    33 raw
        rep("bb", 32),                   // Sha256    32 raw
        rep("cc", 20),                   // Addr      20 raw
        rep("dd", 64),                   // Point     64 raw
        rep("11", 64),                   // P256Point 64 raw  <- was framed "40" + 64
        rep("22", 96),                   // P384Point 96 raw  <- was framed "4c60" + 96
        format!("443044{}", rep("ee", 66)), // Sig        framed <len><data>
        format!("08{}", rep("ff", 8)),   // RabinSig   framed <len><data>
        "020011",                        // ByteString framed <len><data>
    )
}

fn bytes_of(v: &SdkValue) -> String {
    match v {
        SdkValue::Bytes(b) => b.clone(),
        other => panic!("expected SdkValue::Bytes, got {other:?}"),
    }
}

#[test]
fn curve_point_cross_sdk_golden_serialize() {
    let want = cross_sdk_golden();
    assert_eq!(want.len() / 2, 399, "golden must be 399 bytes");
    assert_eq!(
        serialize_state(&curve_point_fields(), &curve_point_values()),
        want,
    );
}

#[test]
fn curve_point_cross_sdk_golden_deserialize() {
    let back = deserialize_state(&curve_point_fields(), &cross_sdk_golden());
    assert!(matches!(back["n"], SdkValue::Int(1)), "n: {:?}", back["n"]);
    assert!(matches!(back["flag"], SdkValue::Bool(true)), "flag: {:?}", back["flag"]);
    let input = curve_point_values();
    for k in ["pk", "h", "ad", "pt", "p256", "p384", "sig", "rab", "bs"] {
        assert_eq!(bytes_of(&back[k]), bytes_of(&input[k]), "field {k}");
    }
}

#[test]
fn curve_point_lone_field_round_trip() {
    for (field_type, size, fill) in [("P256Point", 64usize, "11"), ("P384Point", 96, "22")] {
        let fields = vec![field("v", field_type, 0)];
        let v = rep(fill, size);
        let mut values: HashMap<String, SdkValue> = HashMap::new();
        values.insert("v".into(), SdkValue::Bytes(v.clone()));
        let hex = serialize_state(&fields, &values);
        assert_eq!(hex, v, "{field_type} must serialize raw");
        assert_eq!(hex.len() / 2, size, "{field_type} width");
        assert_eq!(bytes_of(&deserialize_state(&fields, &hex)["v"]), v);
    }
}

#[test]
fn curve_point_controls_unchanged() {
    for (field_type, size) in [("Point", 64usize), ("PubKey", 33), ("Sha256", 32)] {
        let v = rep("ab", size);
        let mut values: HashMap<String, SdkValue> = HashMap::new();
        values.insert("v".into(), SdkValue::Bytes(v.clone()));
        assert_eq!(
            serialize_state(&[field("v", field_type, 0)], &values),
            v,
            "{field_type} control must stay raw",
        );
    }
    for field_type in ["ByteString", "Sig", "RabinSig"] {
        let v = rep("ab", 64);
        let mut values: HashMap<String, SdkValue> = HashMap::new();
        values.insert("v".into(), SdkValue::Bytes(v.clone()));
        assert_eq!(
            serialize_state(&[field("v", field_type, 0)], &values),
            format!("40{v}"),
            "{field_type} control must stay framed",
        );
    }
}
