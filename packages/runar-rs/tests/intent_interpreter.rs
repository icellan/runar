//! Intent-intrinsics ANF-interpreter coverage (Rust tier).
//!
//! Rust-tier port of
//! `packages/runar-testing/src/__tests__/intent-intrinsics-interpreter.test.ts`.
//! Exercises the three intent-covenant intrinsics
//! (`extractPrevOutputScript`, `requireOutputP2PKH`, `currentBlockHeight`)
//! plus a `len(...)`-driven readonly-branch case, all consumed through
//! the new `execute_with_witness` entry point on the Rust ANF interpreter.
//!
//! The TS reference operates on the source-level AST and the witness
//! channel is owned by `TestContract` (setters into the AST interpreter).
//! Rust has no source-level interpreter — the equivalent guarantee
//! lives in `compute_new_state` / `execute_strict` / `execute_with_witness`
//! over the ANF IR. The pre-compiled IR for each fixture is loaded from
//! `conformance/tests/<fixture>/expected-ir.json`, which is what every
//! tier-conformance run produces.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use runar_lang::sdk::SdkValue;
use runar_lang::sdk::anf_interpreter::{
    execute_with_witness, ANFProgram, IntentInterpreterError, IntentWitnessContext,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn conformance_ir(fixture: &str) -> ANFProgram {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir
            .join("conformance/tests")
            .join(fixture)
            .join("expected-ir.json");
        if candidate.is_file() {
            let data = fs::read_to_string(&candidate)
                .unwrap_or_else(|e| panic!("read {}: {}", candidate.display(), e));
            return serde_json::from_str(&data)
                .unwrap_or_else(|e| panic!("parse {}: {}", candidate.display(), e));
        }
        if !dir.pop() {
            panic!(
                "could not locate conformance/tests/{}/expected-ir.json walking up from {}",
                fixture,
                env!("CARGO_MANIFEST_DIR")
            );
        }
    }
}

fn hash256(bytes: &[u8]) -> Vec<u8> {
    let a = Sha256::digest(bytes);
    Sha256::digest(&a).to_vec()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 2 <= bytes.len() {
        let hi = match bytes[i] {
            b'0'..=b'9' => bytes[i] - b'0',
            b'a'..=b'f' => bytes[i] - b'a' + 10,
            b'A'..=b'F' => bytes[i] - b'A' + 10,
            _ => panic!("bad hex"),
        };
        let lo = match bytes[i + 1] {
            b'0'..=b'9' => bytes[i + 1] - b'0',
            b'a'..=b'f' => bytes[i + 1] - b'a' + 10,
            b'A'..=b'F' => bytes[i + 1] - b'A' + 10,
            _ => panic!("bad hex"),
        };
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Build a canonical 34-byte P2PKH output: 8 LE amount ‖ 1976a914 ‖ pkh ‖ 88ac.
fn p2pkh_output(amount: u64, pkh: &[u8]) -> Vec<u8> {
    assert_eq!(pkh.len(), 20, "pkh must be 20 bytes");
    let mut out = Vec::with_capacity(34);
    out.extend_from_slice(&amount.to_le_bytes());
    out.extend_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
    out.extend_from_slice(pkh);
    out.extend_from_slice(&[0x88, 0xac]);
    out
}

// ---------------------------------------------------------------------------
// intent-prev-output-script
// ---------------------------------------------------------------------------

fn intent_prev_output_args(change_amount: i64) -> HashMap<String, SdkValue> {
    let mut args = HashMap::new();
    // Continuation params — values are arbitrary; the witness-mode
    // executor strips the trailing continuation assert that consumes them.
    args.insert("_changePKH".to_string(), SdkValue::Bytes("00".repeat(20)));
    args.insert("_changeAmount".to_string(), SdkValue::Int(change_amount));
    args.insert("_newAmount".to_string(), SdkValue::Int(50_000));
    args
}

#[test]
fn intent_prev_output_script_success() {
    let anf = conformance_ir("intent-prev-output-script");
    let prev_out_script = hex_to_bytes("76a91400112233445566778899aabbccddeeff0011223388ac");
    let expected_hash = hash256(&prev_out_script);

    // Constructor params in declaration order: [expectedHash, count] —
    // both are readonly/initialised slots. count is mutable but we still
    // supply it through current_state.
    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&expected_hash)),
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_prev_out_script(0, &prev_out_script);

    let res = execute_with_witness(
        &anf,
        "bind",
        &state,
        &intent_prev_output_args(45_000),
        &constructor_args,
        &witness,
    );
    let (new_state, _, _) = res.expect("expected successful call");
    assert_eq!(new_state.get("count"), Some(&SdkValue::Int(1)));
}

#[test]
fn intent_prev_output_script_wrong_hash_asserts() {
    let anf = conformance_ir("intent-prev-output-script");
    let prev_out_script = hex_to_bytes("76a91400112233445566778899aabbccddeeff0011223388ac");
    let expected_hash = hash256(&prev_out_script);

    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&expected_hash)),
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    // Different bytes → different hash256.
    witness.set_prev_out_script(0, &hex_to_bytes("deadbeef"));

    let err = execute_with_witness(
        &anf,
        "bind",
        &state,
        &intent_prev_output_args(45_000),
        &constructor_args,
        &witness,
    )
    .expect_err("expected assertion failure on wrong witness");
    match err {
        IntentInterpreterError::Assertion(_) => {}
        other => panic!("expected Assertion, got {:?}", other),
    }
}

#[test]
fn intent_prev_output_script_missing_witness_errors() {
    let anf = conformance_ir("intent-prev-output-script");
    let prev_out_script = hex_to_bytes("76a91400112233445566778899aabbccddeeff0011223388ac");
    let expected_hash = hash256(&prev_out_script);

    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&expected_hash)),
        SdkValue::Int(0),
    ];

    // Intentionally omit set_prev_out_script.
    let witness = IntentWitnessContext::new();

    let err = execute_with_witness(
        &anf,
        "bind",
        &state,
        &intent_prev_output_args(45_000),
        &constructor_args,
        &witness,
    )
    .expect_err("expected missing-witness error");
    match err {
        IntentInterpreterError::MissingWitness(msg) => {
            assert!(
                msg.contains("requires witness bytes"),
                "msg should mention witness requirement: {}",
                msg
            );
            assert!(msg.contains("_prev_out_script(0") || msg.contains("(0"));
        }
        other => panic!("expected MissingWitness, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// intent-output-p2pkh
// ---------------------------------------------------------------------------

fn intent_p2pkh_args() -> HashMap<String, SdkValue> {
    let mut args = HashMap::new();
    args.insert("_changePKH".to_string(), SdkValue::Bytes("00".repeat(20)));
    args.insert("_changeAmount".to_string(), SdkValue::Int(45_000));
    args.insert("_newAmount".to_string(), SdkValue::Int(50_000));
    args
}

#[test]
fn intent_output_p2pkh_success() {
    let anf = conformance_ir("intent-output-p2pkh");
    let bond_pkh = hex_to_bytes("00112233445566778899aabbccddeeff00112233");
    let bond_amount: u64 = 5000;
    let serialised = p2pkh_output(bond_amount, &bond_pkh);
    let output_hash = hash256(&serialised);

    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&bond_pkh)),
        SdkValue::Int(bond_amount as i64),
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_serialised_outputs(&serialised);
    witness.set_mock_preimage_bytes_field("outputHash", &output_hash);

    let res = execute_with_witness(
        &anf,
        "payBond",
        &state,
        &intent_p2pkh_args(),
        &constructor_args,
        &witness,
    );
    let (new_state, _, _) = res.expect("expected successful call");
    assert_eq!(new_state.get("count"), Some(&SdkValue::Int(1)));
}

#[test]
fn intent_output_p2pkh_wrong_pkh_asserts() {
    let anf = conformance_ir("intent-output-p2pkh");
    let bond_pkh = hex_to_bytes("00112233445566778899aabbccddeeff00112233");
    let bond_amount: u64 = 5000;
    let wrong_pkh = hex_to_bytes("ffffffffffffffffffffffffffffffffffffffff");
    let wrong_serialised = p2pkh_output(bond_amount, &wrong_pkh);
    let wrong_output_hash = hash256(&wrong_serialised);

    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&bond_pkh)),
        SdkValue::Int(bond_amount as i64),
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_serialised_outputs(&wrong_serialised);
    // hashOutputs matches the (wrong) serialised — outer assert passes,
    // inner substr-vs-expected assert fires.
    witness.set_mock_preimage_bytes_field("outputHash", &wrong_output_hash);

    let err = execute_with_witness(
        &anf,
        "payBond",
        &state,
        &intent_p2pkh_args(),
        &constructor_args,
        &witness,
    )
    .expect_err("expected assertion failure on wrong PKH");
    match err {
        IntentInterpreterError::Assertion(_) => {}
        other => panic!("expected Assertion, got {:?}", other),
    }
}

#[test]
fn intent_output_p2pkh_wrong_output_hash_asserts() {
    let anf = conformance_ir("intent-output-p2pkh");
    let bond_pkh = hex_to_bytes("00112233445566778899aabbccddeeff00112233");
    let bond_amount: u64 = 5000;
    let serialised = p2pkh_output(bond_amount, &bond_pkh);

    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Bytes(bytes_to_hex(&bond_pkh)),
        SdkValue::Int(bond_amount as i64),
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_serialised_outputs(&serialised);
    // Zero outputHash — outer hash assert fails.
    witness.set_mock_preimage_bytes_field("outputHash", &[0u8; 32]);

    let err = execute_with_witness(
        &anf,
        "payBond",
        &state,
        &intent_p2pkh_args(),
        &constructor_args,
        &witness,
    )
    .expect_err("expected assertion failure on wrong outputHash");
    match err {
        IntentInterpreterError::Assertion(_) => {}
        other => panic!("expected Assertion, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// intent-current-block-height
// ---------------------------------------------------------------------------

fn intent_block_args() -> HashMap<String, SdkValue> {
    let mut args = HashMap::new();
    args.insert("_changePKH".to_string(), SdkValue::Bytes("00".repeat(20)));
    args.insert("_changeAmount".to_string(), SdkValue::Int(45_000));
    args.insert("_newAmount".to_string(), SdkValue::Int(50_000));
    args
}

#[test]
fn intent_current_block_height_success() {
    let anf = conformance_ir("intent-current-block-height");
    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Int(1_000_000), // deadline
        SdkValue::Int(0),         // count
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_mock_preimage_field("locktime", 500_000);

    let res = execute_with_witness(
        &anf,
        "spend",
        &state,
        &intent_block_args(),
        &constructor_args,
        &witness,
    );
    let (new_state, _, _) = res.expect("expected successful call");
    assert_eq!(new_state.get("count"), Some(&SdkValue::Int(1)));
}

#[test]
fn intent_current_block_height_too_late_asserts() {
    let anf = conformance_ir("intent-current-block-height");
    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(0));
    let constructor_args = vec![
        SdkValue::Int(100), // deadline
        SdkValue::Int(0),
    ];

    let mut witness = IntentWitnessContext::new();
    witness.set_mock_preimage_field("locktime", 999_999);

    let err = execute_with_witness(
        &anf,
        "spend",
        &state,
        &intent_block_args(),
        &constructor_args,
        &witness,
    )
    .expect_err("expected locktime > deadline assertion");
    match err {
        IntentInterpreterError::Assertion(_) => {}
        other => panic!("expected Assertion, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// branched-readonly-len
// ---------------------------------------------------------------------------

fn branched_args(scratch_hex: &str) -> HashMap<String, SdkValue> {
    let mut args = HashMap::new();
    args.insert("scratch".to_string(), SdkValue::Bytes(scratch_hex.to_string()));
    args.insert("_changePKH".to_string(), SdkValue::Bytes("00".repeat(20)));
    args.insert("_changeAmount".to_string(), SdkValue::Int(45_000));
    args
}

#[test]
fn branched_readonly_len_then_branch() {
    let anf = conformance_ir("branched-readonly-len");
    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(10));
    state.insert("tag".to_string(), SdkValue::Bytes("00".to_string()));
    let constructor_args = vec![SdkValue::Int(10), SdkValue::Bytes("00".to_string())];

    let witness = IntentWitnessContext::new();

    let res = execute_with_witness(
        &anf,
        "spend",
        &state,
        &branched_args("aabbcc"),
        &constructor_args,
        &witness,
    );
    let (new_state, _, _) = res.expect("expected successful call");
    assert_eq!(new_state.get("count"), Some(&SdkValue::Int(11)));
    assert_eq!(
        new_state.get("tag"),
        Some(&SdkValue::Bytes("aabbcc".to_string()))
    );
}

#[test]
fn branched_readonly_len_else_branch() {
    let anf = conformance_ir("branched-readonly-len");
    let mut state: HashMap<String, SdkValue> = HashMap::new();
    state.insert("count".to_string(), SdkValue::Int(10));
    state.insert("tag".to_string(), SdkValue::Bytes("aa".to_string()));
    let constructor_args = vec![SdkValue::Int(10), SdkValue::Bytes("aa".to_string())];

    let witness = IntentWitnessContext::new();

    let res = execute_with_witness(
        &anf,
        "spend",
        &state,
        &branched_args(""),
        &constructor_args,
        &witness,
    );
    let (new_state, _, _) = res.expect("expected successful call");
    assert_eq!(new_state.get("count"), Some(&SdkValue::Int(9)));
    assert_eq!(
        new_state.get("tag"),
        Some(&SdkValue::Bytes("3030".to_string()))
    );
}
