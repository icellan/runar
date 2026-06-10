// The native Rust contract module is omitted because the canonical
// CovenantVault source uses hex string literals (e.g. "1976a914") that the
// Rúnar Rust-DSL parser interprets as ByteString constants but native Rust
// passes as `&str`, which the runtime `cat(&[u8], &[u8])` rejects. Instead,
// we exercise the contract through the same path the SDK uses on-chain:
//   1. compile the source to ANF IR via the Rust compiler crate
//   2. JSON-round-trip into the SDK's anf_interpreter::ANFProgram
//   3. run methods through anf_interpreter::execute_with_witness, which is
//      the Rust-tier port of the TS reference's AST interpreter and
//      implements the same outputHash-mock semantics
//      (IntentWitnessContext::set_mock_preimage_bytes_field("outputHash", ...)).
//
// This is intentionally heavier than other tiers' tests — see
// packages/runar-rs/src/prelude.rs:cat for the underlying constraint.

use std::collections::HashMap;

use runar::prelude::*;
use runar::sdk::anf_interpreter::{
    execute_with_witness, ANFProgram, IntentInterpreterError, IntentWitnessContext,
};
use runar::sdk::types::SdkValue;

const SOURCE: &str = include_str!("CovenantVault.runar.rs");
const FILE_NAME: &str = "CovenantVault.runar.rs";

const MIN_AMOUNT: i64 = 5000;

/// Compile the contract source through the Rust compiler frontend, then
/// JSON-round-trip the resulting IR into the SDK's interpreter shape.
fn load_program() -> ANFProgram {
    let ir = runar_compiler_rust::compile_source_str_to_ir(SOURCE, Some(FILE_NAME))
        .expect("compile_source_str_to_ir");
    let json = serde_json::to_string(&ir).expect("ANFProgram -> json");
    serde_json::from_str(&json).expect("json -> sdk ANFProgram")
}

/// Build the same byte string the on-chain covenant builds for its expected
/// P2PKH output: <8-byte LE amount> ‖ 1976a914 ‖ <pkh> ‖ 88ac.
fn p2pkh_output(amount: i64, pkh: &[u8]) -> Vec<u8> {
    let amt = num2bin(&amount, 8);
    let mut out = Vec::with_capacity(8 + 4 + 20 + 2);
    out.extend_from_slice(&amt);
    out.extend_from_slice(&[0x19, 0x76, 0xa9, 0x14]);
    out.extend_from_slice(pkh);
    out.extend_from_slice(&[0x88, 0xac]);
    out
}

fn constructor_args() -> Vec<SdkValue> {
    vec![
        SdkValue::Bytes(hex_str(ALICE.pub_key)),
        SdkValue::Bytes(hex_str(BOB.pub_key_hash)),
        SdkValue::Int(MIN_AMOUNT),
    ]
}

fn spend_args() -> HashMap<String, SdkValue> {
    let sig = ALICE.sign_test_message();
    let mut m = HashMap::new();
    m.insert("sig".to_string(), SdkValue::Bytes(hex_str(&sig)));
    // Preimage is unused by the SDK interpreter for the outputHash check;
    // extractOutputHash reads from IntentWitnessContext directly.
    m.insert(
        "txPreimage".to_string(),
        SdkValue::Bytes(hex_str(&vec![0u8; 181])),
    );
    m
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Call spend through the SDK interpreter with `outputs_bytes` committed as
/// the spending transaction's hashOutputs preimage.
fn call_spend(outputs_bytes: &[u8]) -> Result<(), IntentInterpreterError> {
    let program = load_program();
    let mut witness = IntentWitnessContext::new();
    let h = hash256(outputs_bytes);
    witness.set_mock_preimage_bytes_field("outputHash", &h);
    execute_with_witness(
        &program,
        "spend",
        &HashMap::new(),
        &spend_args(),
        &constructor_args(),
        &witness,
    )
    .map(|_| ())
}

#[test]
fn test_compile() {
    runar::compile_check(SOURCE, FILE_NAME).unwrap();
}

#[test]
fn test_happy_path() {
    let expected = p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash);
    call_spend(&expected).expect("happy path must succeed");
}

// -- Adversarial: wrong output count -----------------------------------------

#[test]
fn test_rejects_zero_outputs() {
    let err = call_spend(&[]).expect_err("zero-output covenant must fail");
    assert!(matches!(err, IntentInterpreterError::Assertion(_)), "got {err:?}");
}

#[test]
fn test_rejects_extra_output() {
    let required = p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash);
    let extra_pkh = [0xccu8; 20];
    let extra = p2pkh_output(1000, &extra_pkh);
    let mut combined = required;
    combined.extend_from_slice(&extra);
    let err = call_spend(&combined).expect_err("extra-output must fail");
    assert!(matches!(err, IntentInterpreterError::Assertion(_)), "got {err:?}");
}

// -- Adversarial: swapped output order ---------------------------------------

#[test]
fn test_rejects_reordered_outputs() {
    let required = p2pkh_output(MIN_AMOUNT, BOB.pub_key_hash);
    let other_pkh = [0xccu8; 20];
    let other = p2pkh_output(MIN_AMOUNT, &other_pkh);
    let mut combined = other;
    combined.extend_from_slice(&required); // unauthorised output first
    let err = call_spend(&combined).expect_err("reordered outputs must fail");
    assert!(matches!(err, IntentInterpreterError::Assertion(_)), "got {err:?}");
}

// -- Adversarial: value at boundary ------------------------------------------

#[test]
fn test_rejects_amount_minus_one() {
    let candidate = p2pkh_output(MIN_AMOUNT - 1, BOB.pub_key_hash);
    let err = call_spend(&candidate).expect_err("amount - 1 must fail");
    assert!(matches!(err, IntentInterpreterError::Assertion(_)), "got {err:?}");
}

#[test]
fn test_rejects_amount_plus_one() {
    let candidate = p2pkh_output(MIN_AMOUNT + 1, BOB.pub_key_hash);
    let err = call_spend(&candidate).expect_err("amount + 1 must fail");
    assert!(matches!(err, IntentInterpreterError::Assertion(_)), "got {err:?}");
}
