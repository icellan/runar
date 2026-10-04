//! The state section is framed `<len><data>`, never MINIMALDATA.
//!
//! `SCRIPT_VERIFY_MINIMALDATA` applies to pushes the interpreter EXECUTES —
//! unlocking scripts and spliced constructor args, which `encode_push_data`
//! still handles (see encode_push_data_minimaldata.rs). The state section is
//! raw data after `OP_RETURN` in the locking script: never executed, never
//! MINIMALDATA-checked, and read back by the compiler's on-chain state codec
//! (`emitPushDataEncode` in 05-stack-lower.ts), which understands only
//! `<len><data>`.
//!
//! #110 applied the MINIMALDATA short-circuit to the state serializer in all
//! seven SDKs and none of the seven compilers. A 1-byte `0x05` state field
//! then serialised off-chain as `55` while the script rebuilt it as `0105`,
//! so the continuation hash never matched (unspendable), and a contract
//! DEPLOYED with such a value could not be spent at all (the on-chain reader
//! takes `0x55` as a length-85 push).

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, serialize_state};
use runar_lang::sdk::types::StateField;
use runar_lang::sdk::SdkValue;

fn byte_string_field() -> Vec<StateField> {
    vec![StateField {
        name: "b".to_string(),
        field_type: "ByteString".to_string(),
        index: 0,
        initial_value: None,
        fixed_array: None,
    }]
}

fn encode(payload: &str) -> String {
    let mut values: HashMap<String, SdkValue> = HashMap::new();
    values.insert("b".to_string(), SdkValue::Bytes(payload.to_string()));
    serialize_state(&byte_string_field(), &values)
}

#[test]
fn state_1_byte_op_n_range_stays_a_direct_push() {
    for n in 1u8..=16 {
        let payload = format!("{:02x}", n);
        assert_eq!(
            encode(&payload),
            format!("01{}", payload),
            "1-byte state value 0x{:02x} must stay <len><data>, not OP_{}",
            n,
            n
        );
    }
}

#[test]
fn state_1_byte_0x81_is_not_op_1negate() {
    assert_eq!(encode("81"), "0181");
}

#[test]
fn state_1_byte_zero_is_a_direct_push() {
    assert_eq!(encode("00"), "0100");
}

#[test]
fn state_empty_is_a_zero_length_push() {
    assert_eq!(encode(""), "00");
}

#[test]
fn state_values_outside_the_op_n_range_are_unchanged() {
    assert_eq!(encode("11"), "0111");
    assert_eq!(encode("0011"), "020011");
}

#[test]
fn state_round_trips_for_every_single_byte_value() {
    let fields = byte_string_field();
    for byte in 0u16..=0xff {
        let payload = format!("{:02x}", byte);
        let encoded = encode(&payload);
        let decoded = deserialize_state(&fields, &encoded)
            .unwrap_or_else(|e| panic!("deserialize_state refused a well-formed blob {encoded:?}: {e}"));
        match decoded.get("b") {
            Some(SdkValue::Bytes(h)) => assert_eq!(*h, payload, "roundtrip 0x{:02x}", byte),
            other => panic!("roundtrip 0x{:02x}: unexpected value {:?}", byte, other),
        }
    }
}

/// N-044: the compiler's on-chain state reader and writer frame a ByteString
/// with an UNSIGNED length — `<len>` below 76, `4c <len8>`, `4d <len16 LE>`,
/// `4e <len32 LE>` — and the covenant only accepts a continuation whose state
/// bytes equal the SDK's. Hand-written expected headers at every boundary where
/// a signed reading of the length used to differ (0x80, 0x81.., 0x8000,
/// 0xffff) and where PUSHDATA4 starts. The on-chain side is run against the
/// same frames by packages/runar-testing/src/__tests__/n044-state-length-sign-spend.
#[test]
fn state_pushdata_length_boundaries_match_the_on_chain_frame() {
    let cases: &[(usize, &str)] = &[
        (75, "4b"), (76, "4c4c"), (127, "4c7f"), (128, "4c80"), (129, "4c81"),
        (255, "4cff"), (256, "4d0001"), (32767, "4dff7f"), (32768, "4d0080"),
        (65535, "4dffff"), (65536, "4e00000100"),
    ];
    let fields = byte_string_field();
    for &(n, header) in cases {
        let payload = "ab".repeat(n);
        let encoded = encode(&payload);
        assert_eq!(&encoded[..header.len()], header, "len {n}: frame header");
        assert_eq!(encoded.len(), header.len() + payload.len(), "len {n}: frame length");
        let decoded = deserialize_state(&fields, &encoded)
            .unwrap_or_else(|e| panic!("len {n}: deserialize_state refused its own frame: {e}"));
        match decoded.get("b") {
            Some(SdkValue::Bytes(h)) => assert_eq!(*h, payload, "len {n}: round-trip"),
            other => panic!("len {n}: unexpected value {:?}", other),
        }
    }
}
