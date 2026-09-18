//! C2 — `deserialize_state` failed OPEN.
//!
//! The state blob is read back out of a deployed locking script's OP_RETURN
//! tail (`RunarContract::from_utxo` -> `extract_state_from_script` ->
//! `deserialize_state`). That script is something any third party can
//! construct, so the blob is untrusted input — and the caller then builds and
//! SIGNS a continuation output committing to whatever state came back.
//!
//! Every arm of the Rust decoder bounds-checked, returned a DEFAULT and then
//! advanced the NOMINAL width anyway (`state.rs:626+`), desynchronising every
//! later field; `decode_push_data`'s `OP_PUSHDATA{1,2,4}` length-prefix slices
//! were unchecked and PANICKED; and `deserialize_state` had no trailing-byte
//! check at all. Measured before the fix, `cargo test` exit 0:
//!
//! ```text
//! 2a00000000000000            a,b bigint    -> [("a", Int(42)), ("b", Int(0))]
//! 2a.. + 01.. + deadbeef      a,b bigint    -> [("a", Int(42)), ("b", Int(1))]
//! 4b aaaaaa                   m ByteString  -> [("m", Bytes(""))]
//! aa x10                      k PubKey      -> [("k", Bytes(""))]
//! 55                          m ByteString  -> [("m", Bytes(""))]
//! 4c                          m ByteString  -> PANIC at src/sdk/state.rs:738
//! ```
//!
//! The semantics here are TypeScript's (C28, `packages/runar-sdk/src/state.ts`,
//! test `c28-state-strict.test.ts`): refuse rather than default, and refuse
//! trailing bytes. All seven SDKs read the SAME wire format, so the triggering
//! conditions must be identical even though each tier uses its own error type.

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, extract_state_from_script, serialize_state};
use runar_lang::sdk::types::{RunarArtifact, SdkValue, StateField};

fn f(name: &str, t: &str, index: usize) -> StateField {
    StateField {
        name: name.to_string(),
        field_type: t.to_string(),
        index,
        initial_value: None,
        fixed_array: None,
    }
}

/// A minimal artifact carrying only the state fields under test.
fn artifact_with(fields: &[StateField]) -> RunarArtifact {
    let state_fields: Vec<serde_json::Value> = fields
        .iter()
        .map(|f| serde_json::json!({ "name": f.name, "type": f.field_type, "index": f.index }))
        .collect();
    serde_json::from_value(serde_json::json!({
        "version": "1",
        "contractName": "C2",
        "abi": { "constructor": { "params": [] }, "methods": [] },
        "script": "",
        "stateFields": state_fields,
    }))
    .expect("building the test artifact")
}

fn two_ints() -> Vec<StateField> {
    vec![f("a", "bigint", 0), f("b", "bigint", 1)]
}
fn bytestr() -> Vec<StateField> {
    vec![f("blob", "ByteString", 0)]
}

/// Every fixed-width type and its declared width in bytes.
const FIXED_WIDTHS: &[(&str, usize)] = &[
    ("boolean", 1), ("bool", 1), ("bigint", 8), ("int", 8),
    ("PubKey", 33), ("Addr", 20), ("Ripemd160", 20), ("Sha256", 32),
    ("Point", 64), ("P256Point", 64), ("P384Point", 96),
];

fn values(pairs: &[(&str, SdkValue)]) -> HashMap<String, SdkValue> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

// ---------------------------------------------------------------------------
// The five hostile blobs from the finding, verbatim.
// ---------------------------------------------------------------------------

#[test]
fn hostile_blobs_are_refused_not_decoded() {
    let cases: Vec<(&str, Vec<StateField>, String, &str)> = vec![
        ("truncated trailing bigint", two_ints(), "2a00000000000000".into(), "truncat"),
        ("trailing bytes", two_ints(), "2a000000000000000100000000000000deadbeef".into(), "trailing"),
        ("push payload runs past the end", bytestr(), "4baaaaaa".into(), "truncat"),
        ("short PubKey", vec![f("k", "PubKey", 0)], "aa".repeat(10), "truncat"),
        ("0x55 is not a push opcode", bytestr(), "55".into(), "is not a push opcode"),
    ];
    for (label, fields, blob, want) in cases {
        match deserialize_state(&fields, &blob) {
            Ok(v) => panic!("{label}: decoded a hostile blob instead of refusing it: {v:?}"),
            Err(e) => assert!(
                e.to_lowercase().contains(want),
                "{label}: error {e:?} does not mention {want:?}",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Truncation, exhaustively
// ---------------------------------------------------------------------------

#[test]
fn every_fixed_width_arm_refuses_a_short_blob() {
    for (ty, width) in FIXED_WIDTHS {
        let fields = vec![f("v", ty, 0)];
        let short = "aa".repeat(width - 1);
        assert!(
            deserialize_state(&fields, &short).is_err(),
            "{ty}: accepted a {}-byte blob for a {width}-byte field",
            width - 1,
        );
    }
}

/// The `OP_PUSHDATA{1,2,4}` length-prefix slices used to be unchecked and
/// PANICKED — a different failure mode from a wrong value. Every one must now
/// be a typed refusal.
#[test]
fn push_framing_is_bounds_checked_and_never_panics() {
    for blob in [
        "4c",         // OP_PUSHDATA1, no length byte
        "4c05aabb",   // declares 5 bytes, 2 supplied
        "4d",         // OP_PUSHDATA2, no length bytes
        "4d00",       // half a length
        "4d0500aabb", // declares 5, 2 supplied
        "4e",         // OP_PUSHDATA4, no length bytes
        "4e05000000", // declares 5, none supplied
        "05aabb",     // direct push declares 5, 2 supplied
    ] {
        let r = std::panic::catch_unwind(|| deserialize_state(&bytestr(), blob));
        match r {
            Err(_) => panic!("{blob}: panicked instead of returning a typed error"),
            Ok(Ok(v)) => panic!("{blob}: accepted malformed push framing: {v:?}"),
            Ok(Err(_)) => {}
        }
    }
}

#[test]
fn missing_push_opcode_byte_entirely() {
    let fields = vec![f("n", "bigint", 0), f("blob", "ByteString", 1)];
    let full = serialize_state(
        &fields,
        &values(&[("n", SdkValue::Int(1)), ("blob", SdkValue::Bytes("aa".into()))]),
    );
    let err = deserialize_state(&fields, &full[..16]).unwrap_err();
    assert!(err.to_lowercase().contains("truncat"), "{err}");
}

#[test]
fn truncated_fixed_array_element() {
    use runar_lang::sdk::types::FixedArrayInfo;
    let fields = vec![StateField {
        name: "board".into(),
        field_type: "FixedArray<bigint, 3>".into(),
        index: 0,
        initial_value: None,
        fixed_array: Some(FixedArrayInfo {
            synthetic_names: vec!["board__0".into(), "board__1".into(), "board__2".into()],
            element_type: "bigint".into(),
            length: 3,
        }),
    }];
    let full = serialize_state(
        &fields,
        &values(&[(
            "board",
            SdkValue::Array(vec![SdkValue::Int(1), SdkValue::Int(2), SdkValue::Int(3)]),
        )]),
    );
    assert_eq!(full.len(), 48);
    assert!(deserialize_state(&fields, &full[..40]).is_err());
}

#[test]
fn odd_length_blob_is_refused() {
    assert!(deserialize_state(&[f("count", "bigint", 0)], "00112233445566778").is_err());
}

// ---------------------------------------------------------------------------
// Overlong tails
// ---------------------------------------------------------------------------

#[test]
fn trailing_bytes_are_refused() {
    let one = vec![f("a", "bigint", 0)];
    let full = serialize_state(&one, &values(&[("a", SdkValue::Int(42))]));
    assert!(deserialize_state(&one, &format!("{full}ff")).unwrap_err().contains("trailing"));

    let bs = bytestr();
    let full = serialize_state(&bs, &values(&[("blob", SdkValue::Bytes("aabbcc".into()))]));
    assert!(deserialize_state(&bs, &format!("{full}00")).unwrap_err().contains("trailing"));

    let full = serialize_state(
        &two_ints(),
        &values(&[("a", SdkValue::Int(1)), ("b", SdkValue::Int(2))]),
    );
    assert!(deserialize_state(&one, &full).unwrap_err().contains("trailing"));
}

#[test]
fn extract_state_from_script_surfaces_a_corrupted_continuation() {
    let fields = vec![f("count", "bigint", 0)];
    let artifact = artifact_with(&fields);
    let state_hex = serialize_state(&fields, &values(&[("count", SdkValue::Int(5))]));
    let script = format!("516a{state_hex}ff");
    assert!(extract_state_from_script(&artifact, &script).is_err());
}

// ---------------------------------------------------------------------------
// CONTROLS — a guard that rejects legitimate state is just as broken.
// ---------------------------------------------------------------------------

#[test]
fn control_well_formed_state_still_round_trips() {
    let fields = vec![
        f("count", "bigint", 0),
        f("active", "boolean", 1),
        f("owner", "PubKey", 2),
        f("blob", "ByteString", 3),
    ];
    let owner = "cd".repeat(33);
    let vals = values(&[
        ("count", SdkValue::Int(-9)),
        ("active", SdkValue::Bool(true)),
        ("owner", SdkValue::Bytes(owner.clone())),
        ("blob", SdkValue::Bytes("deadbeef".into())),
    ]);
    let hex = serialize_state(&fields, &vals);
    let got = deserialize_state(&fields, &hex).expect("refused a well-formed blob");
    assert_eq!(got["count"], SdkValue::Int(-9));
    assert_eq!(got["active"], SdkValue::Bool(true));
    assert_eq!(got["owner"], SdkValue::Bytes(owner));
    assert_eq!(got["blob"], SdkValue::Bytes("deadbeef".into()));
}

#[test]
fn control_edge_shaped_but_legitimate_blobs() {
    let bs = bytestr();

    // <len><data>, the compiler's on-chain state codec — NOT the MINIMALDATA
    // opcode form ('55'), which the contract's own script cannot read.
    let hex = serialize_state(&bs, &values(&[("blob", SdkValue::Bytes("05".into()))]));
    assert_eq!(hex, "0105");
    assert_eq!(
        deserialize_state(&bs, &hex).expect("refused a 1-byte ByteString")["blob"],
        SdkValue::Bytes("05".into()),
    );

    let hex = serialize_state(&bs, &values(&[("blob", SdkValue::Bytes(String::new()))]));
    assert_eq!(
        deserialize_state(&bs, &hex).expect("refused an empty ByteString")["blob"],
        SdkValue::Bytes(String::new()),
    );

    assert!(deserialize_state(&[], "").expect("refused the empty record").is_empty());

    for n in [75usize, 76, 300] {
        let payload = "ab".repeat(n);
        let hex = serialize_state(&bs, &values(&[("blob", SdkValue::Bytes(payload.clone()))]));
        assert_eq!(
            deserialize_state(&bs, &hex).unwrap_or_else(|e| panic!("refused a {n}-byte push: {e}"))["blob"],
            SdkValue::Bytes(payload),
        );
    }

    for (ty, width) in FIXED_WIDTHS.iter().skip(4) {
        let payload = "7e".repeat(*width);
        let got = deserialize_state(&[f("v", ty, 0)], &payload)
            .unwrap_or_else(|e| panic!("{ty}: refused an exactly-{width}-byte value: {e}"));
        assert_eq!(got["v"], SdkValue::Bytes(payload));
    }

    let fields = vec![f("count", "bigint", 0)];
    let artifact = artifact_with(&fields);
    let state_hex = serialize_state(&fields, &values(&[("count", SdkValue::Int(5))]));
    let got = extract_state_from_script(&artifact, &format!("516a{state_hex}"))
        .expect("refused a well-formed continuation")
        .expect("no state section found");
    assert_eq!(got["count"], SdkValue::Int(5));
}

// ---------------------------------------------------------------------------
// Missing value for a raw fixed-width field — the byte divergence.
//
// Rust silently OMITTED the field (zero bytes for a field the artifact
// declares N bytes wide), Python/Ruby wrote "", Go "<nil>", Java "null", TS
// "undefined". None deploys a state section the contract can read; they just
// corrupt it differently. Refusing is the only answer that is the same
// everywhere. Panics rather than returning an error, matching the contract
// `state_field_i64` already documents for `serialize_state`.
// ---------------------------------------------------------------------------

#[test]
fn serializing_a_missing_raw_fixed_width_field_is_refused() {
    for ty in ["PubKey", "Addr", "Ripemd160", "Sha256", "Point", "P256Point", "P384Point"] {
        let fields = vec![f("v", ty, 0)];
        let r = std::panic::catch_unwind(move || serialize_state(&fields, &HashMap::new()));
        assert!(r.is_err(), "{ty}: serialized a missing value instead of refusing");
    }
}
