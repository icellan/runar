//! round-trip only — absolute pin: packages/runar-rs/tests/state_push_framing.rs (C9, state half)
//! and packages/runar-rs/tests/encode_push_data_minimaldata.rs (S1, ctor-arg half).
//!
//! C9 + S1 — single-byte MINIMALDATA ByteString roundtrip (state + ctor-arg).
//!
//! `encode_push_data` (packages/runar-rs/src/sdk/state.rs) applies the BSV
//! consensus rule `SCRIPT_VERIFY_MINIMALDATA` for single-byte pushes,
//! short-circuiting to `OP_1..OP_16` / `OP_1NEGATE` for payloads
//! `0x01..=0x10` / `0x81`. It ALSO used to short-circuit a 1-byte `0x00`
//! payload to `OP_0` ("00") — but `OP_0` pushes the EMPTY byte array, not a
//! 1-byte `0x00`, so that short-circuit CHANGED THE VALUE. The minimal
//! encoding of a 1-byte `0x00` payload is the direct push `0100`, matching
//! the compiler's canonical `encodePushBytesHex`
//! (packages/runar-compiler/src/passes/push-encoding.ts), which returns
//! `'00'` only for a zero-LENGTH value and otherwise short-circuits solely
//! on `b >= 1 && b <= 16` / `b === 0x81`.
//!
//! Independently, the two decode sites never understood `OP_1..OP_16` /
//! `OP_1NEGATE` as a 1-byte push at all:
//!   * `decode_push_data` (state path, state.rs) handled only `opcode <= 75`
//!     and `0x4c`/`0x4d`/`0x4e`, so those opcodes fell into the "unknown
//!     opcode" arm and yielded an empty value.
//!   * `interpret_script_element`'s default branch (ctor-restore path,
//!     script_utils.rs) forwarded `read_script_element`'s `data_hex`, which
//!     is empty for those opcodes because they carry no separate data bytes.
//!
//! Net effect (both P1): a 1-byte ByteString state field or constructor arg
//! whose value was `00`, `01..10`, or `81` came back WRONG (empty) when
//! restored from chain.

use std::collections::HashMap;

use runar_lang::sdk::state::{deserialize_state, serialize_state};
use runar_lang::sdk::types::{
    Abi, AbiConstructor, AbiMethod, AbiParam, ConstructorSlot, RunarArtifact, StateField,
};
use runar_lang::sdk::{extract_constructor_args, RunarContract, SdkValue};

/// The payload set that exercises every MINIMALDATA short-circuit branch,
/// plus the two control cases (multi-byte and genuinely empty).
const CASES: [(&str, &str); 7] = [
    ("0x00 (must NOT become OP_0)", "00"),
    ("0x01 (OP_1)", "01"),
    ("0x05 (OP_5, mid OP_1..OP_16 range)", "05"),
    ("0x10 (OP_16)", "10"),
    ("0x81 (OP_1NEGATE)", "81"),
    ("multi-byte value", "aabbccdd"),
    ("empty (genuinely OP_0)", ""),
];

// ---------------------------------------------------------------------------
// C9 — state serialize -> deserialize
// ---------------------------------------------------------------------------

#[test]
fn c9_state_bytestring_minimaldata_roundtrip() {
    let fields = vec![StateField {
        name: "b".to_string(),
        field_type: "ByteString".to_string(),
        index: 0,
        initial_value: None,
        fixed_array: None,
    }];

    let mut failures: Vec<String> = Vec::new();

    for (label, payload) in CASES {
        let mut values: HashMap<String, SdkValue> = HashMap::new();
        values.insert("b".to_string(), SdkValue::Bytes(payload.to_string()));

        let encoded = serialize_state(&fields, &values);
        let decoded = deserialize_state(&fields, &encoded);

        let got = match decoded.get("b") {
            Some(SdkValue::Bytes(h)) => h.clone(),
            other => panic!("state roundtrip {}: unexpected value {:?}", label, other),
        };
        if got != payload {
            failures.push(format!(
                "  {}: encoded={:?} -> got {:?}, want {:?}",
                label, encoded, got, payload
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "state ByteString roundtrip failed for {} payload(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// ---------------------------------------------------------------------------
// S1 — ctor arg splice -> extract
// ---------------------------------------------------------------------------

fn ctor_bytestring_artifact() -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "CtorByteString".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor {
                params: vec![AbiParam {
                    name: "b".to_string(),
                    param_type: "ByteString".to_string(),
                    fixed_array: None,
                }],
            },
            methods: vec![AbiMethod {
                name: "noop".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        // Template: OP_CODESEPARATOR-ish filler byte, the ctor-slot OP_0
        // placeholder, then OP_SWAP. Only the slot at byte offset 1 matters.
        script: "ab007c".to_string(),
        asm: None,
        state_fields: None,
        constructor_slots: Some(vec![ConstructorSlot {
            param_index: 0,
            byte_offset: 1,
        }]),
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
    }
}

#[test]
fn s1_ctor_bytestring_minimaldata_roundtrip() {
    let mut failures: Vec<String> = Vec::new();

    for (label, payload) in CASES {
        let artifact = ctor_bytestring_artifact();
        let contract = RunarContract::new(
            ctor_bytestring_artifact(),
            vec![SdkValue::Bytes(payload.to_string())],
        );
        let locking_script = contract.get_locking_script();

        let restored = extract_constructor_args(&artifact, &locking_script)
            .unwrap_or_else(|e| panic!("ctor roundtrip {}: extract failed: {}", label, e));

        let got = match restored.get("b") {
            Some(SdkValue::Bytes(h)) => h.clone(),
            other => panic!("ctor roundtrip {}: unexpected value {:?}", label, other),
        };
        if got != payload {
            failures.push(format!(
                "  {}: lockingScript={:?} -> got {:?}, want {:?}",
                label, locking_script, got, payload
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "ctor ByteString roundtrip failed for {} payload(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
}
