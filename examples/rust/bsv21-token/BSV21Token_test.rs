#[path = "BSV21Token.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;
use runar::sdk::{
    ordinals::{bsv21_deploy_mint, bsv21_transfer, parse_inscription_envelope},
    RunarArtifact, RunarContract, SdkValue, Utxo,
};
use runar_compiler_rust::compile_from_source_str;

const SOURCE: &str = include_str!("BSV21Token.runar.rs");

/// Convert hex to a UTF-8 string.
fn hex_to_utf8(hex: &str) -> String {
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Compile the contract source and deserialize into the SDK's RunarArtifact.
fn compile_artifact() -> RunarArtifact {
    let compiler_artifact = compile_from_source_str(SOURCE, Some("BSV21Token.runar.rs"))
        .expect("BSV21Token must compile");
    let json = serde_json::to_string(&compiler_artifact).expect("artifact JSON");
    serde_json::from_str(&json).expect("SDK artifact deserialize")
}

fn constructor_args() -> Vec<SdkValue> {
    vec![SdkValue::Bytes(
        ALICE
            .pub_key_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
    )]
}

// ---------------------------------------------------------------------------
// Business logic
// ---------------------------------------------------------------------------

#[test]
fn test_unlock_accepts_matching_key() {
    let pk = ALICE.pub_key.to_vec();
    let c = BSV21Token { pub_key_hash: hash160(&pk) };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_rejects_wrong_key() {
    let pk = ALICE.pub_key.to_vec();
    let wrong_pk = BOB.pub_key.to_vec();
    let c = BSV21Token { pub_key_hash: hash160(&pk) };
    c.unlock(&BOB.sign_test_message(), &wrong_pk);
}

// ---------------------------------------------------------------------------
// Compile check (Rúnar frontend: parse -> validate -> typecheck)
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(SOURCE, "BSV21Token.runar.rs").unwrap();
}

#[test]
fn test_compiles_to_artifact() {
    let artifact = compile_artifact();
    assert_eq!(artifact.contract_name, "BSV21Token");
}

// ---------------------------------------------------------------------------
// BSV-21 deploy+mint inscription
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_mint_inscription_with_all_fields() {
    let artifact = compile_artifact();
    let inscription = bsv21_deploy_mint(
        "1000000",
        Some("18"),
        Some("RNR"),
        Some("b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0"),
    );
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script)
        .expect("envelope must parse from locking script");

    assert_eq!(parsed.content_type, "application/bsv-20");
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"deploy+mint""#));
    assert!(json.contains(r#""amt":"1000000""#));
    assert!(json.contains(r#""dec":"18""#));
    assert!(json.contains(r#""sym":"RNR""#));
    assert!(json.contains(
        r#""icon":"b61b0172d95e266c18aea0c624db987e971a5d6d4ebc2aaed85da4642d635735_0""#
    ));
}

#[test]
fn test_deploy_mint_inscription_minimal() {
    let artifact = compile_artifact();
    let inscription = bsv21_deploy_mint("500", None, None, None);
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();
    let json = hex_to_utf8(&parsed.data);

    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"deploy+mint""#));
    assert!(json.contains(r#""amt":"500""#));
    assert!(!json.contains("\"dec\""));
    assert!(!json.contains("\"sym\""));
    assert!(!json.contains("\"icon\""));
}

// ---------------------------------------------------------------------------
// BSV-21 transfer inscription
// ---------------------------------------------------------------------------

#[test]
fn test_transfer_inscription_with_token_id() {
    let artifact = compile_artifact();
    let token_id = "3b313338fa0555aebeaf91d8db1ffebd74773c67c8ad5181ff3d3f51e21e0000_1";
    let inscription = bsv21_transfer(token_id, "100");
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();

    assert_eq!(parsed.content_type, "application/bsv-20");
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"transfer""#));
    assert!(json.contains(&format!(r#""id":"{}""#, token_id)));
    assert!(json.contains(r#""amt":"100""#));
}

// ---------------------------------------------------------------------------
// Round-trip via from_utxo
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_mint_survives_from_utxo_round_trip() {
    let artifact = compile_artifact();
    let inscription = bsv21_deploy_mint("1000000", None, Some("RNR"), None);
    let mut contract = RunarContract::new(artifact.clone(), constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();

    let reconnected = RunarContract::from_utxo(
        artifact,
        &Utxo {
            txid: "00".repeat(32),
            output_index: 0,
            satoshis: 1,
            script: locking_script,
        },
    );

    let insc = reconnected
        .inscription()
        .expect("reconnected contract must carry the inscription");
    assert_eq!(insc.content_type, "application/bsv-20");

    let json = hex_to_utf8(&insc.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"deploy+mint""#));
    assert!(json.contains(r#""amt":"1000000""#));
    assert!(json.contains(r#""sym":"RNR""#));
}

#[test]
fn test_transfer_survives_from_utxo_round_trip() {
    let artifact = compile_artifact();
    let token_id = "abc123_0";
    let inscription = bsv21_transfer(token_id, "50");
    let mut contract = RunarContract::new(artifact.clone(), constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();

    let reconnected = RunarContract::from_utxo(
        artifact,
        &Utxo {
            txid: "00".repeat(32),
            output_index: 0,
            satoshis: 1,
            script: locking_script,
        },
    );

    let insc = reconnected
        .inscription()
        .expect("reconnected contract must carry the inscription");
    let json = hex_to_utf8(&insc.data);
    assert!(json.contains(r#""op":"transfer""#));
    assert!(json.contains(&format!(r#""id":"{}""#, token_id)));
    assert!(json.contains(r#""amt":"50""#));
}
