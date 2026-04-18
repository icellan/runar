#[path = "BSV20Token.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;
use runar::sdk::{
    ordinals::{bsv20_deploy, bsv20_mint, bsv20_transfer, parse_inscription_envelope},
    RunarArtifact, RunarContract, SdkValue, Utxo,
};
use runar_compiler_rust::compile_from_source_str;

const SOURCE: &str = include_str!("BSV20Token.runar.rs");

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
    let compiler_artifact = compile_from_source_str(SOURCE, Some("BSV20Token.runar.rs"))
        .expect("BSV20Token must compile");
    // Round-trip through JSON so the compiler's artifact (Serialize) is
    // deserialized as the SDK's artifact (Deserialize).
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
    let c = BSV20Token { pub_key_hash: hash160(&pk) };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_rejects_wrong_key() {
    let pk = ALICE.pub_key.to_vec();
    let wrong_pk = BOB.pub_key.to_vec();
    let c = BSV20Token { pub_key_hash: hash160(&pk) };
    c.unlock(&BOB.sign_test_message(), &wrong_pk);
}

// ---------------------------------------------------------------------------
// Compile check (Rúnar frontend: parse -> validate -> typecheck)
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(SOURCE, "BSV20Token.runar.rs").unwrap();
}

#[test]
fn test_compiles_to_artifact() {
    let artifact = compile_artifact();
    assert_eq!(artifact.contract_name, "BSV20Token");
}

// ---------------------------------------------------------------------------
// BSV-20 deploy inscription
// ---------------------------------------------------------------------------

#[test]
fn test_deploy_inscription_has_correct_json() {
    let artifact = compile_artifact();
    let inscription = bsv20_deploy("RUNAR", "21000000", Some("1000"), None);
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script)
        .expect("envelope must parse from locking script");

    assert_eq!(parsed.content_type, "application/bsv-20");
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"deploy""#));
    assert!(json.contains(r#""tick":"RUNAR""#));
    assert!(json.contains(r#""max":"21000000""#));
    assert!(json.contains(r#""lim":"1000""#));
}

#[test]
fn test_deploy_inscription_with_decimals() {
    let artifact = compile_artifact();
    let inscription = bsv20_deploy("USDT", "100000000", None, Some("8"));
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""dec":"8""#));
}

// ---------------------------------------------------------------------------
// BSV-20 mint inscription
// ---------------------------------------------------------------------------

#[test]
fn test_mint_inscription_has_correct_json() {
    let artifact = compile_artifact();
    let inscription = bsv20_mint("RUNAR", "1000");
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();

    assert_eq!(parsed.content_type, "application/bsv-20");
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"mint""#));
    assert!(json.contains(r#""tick":"RUNAR""#));
    assert!(json.contains(r#""amt":"1000""#));
}

// ---------------------------------------------------------------------------
// BSV-20 transfer inscription
// ---------------------------------------------------------------------------

#[test]
fn test_transfer_inscription_has_correct_json() {
    let artifact = compile_artifact();
    let inscription = bsv20_transfer("RUNAR", "50");
    let mut contract = RunarContract::new(artifact, constructor_args());
    contract.with_inscription(inscription);

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();

    assert_eq!(parsed.content_type, "application/bsv-20");
    let json = hex_to_utf8(&parsed.data);
    assert!(json.contains(r#""p":"bsv-20""#));
    assert!(json.contains(r#""op":"transfer""#));
    assert!(json.contains(r#""tick":"RUNAR""#));
    assert!(json.contains(r#""amt":"50""#));
}

// ---------------------------------------------------------------------------
// Round-trip via from_utxo
// ---------------------------------------------------------------------------

#[test]
fn test_inscription_survives_from_utxo_round_trip() {
    let artifact = compile_artifact();
    let inscription = bsv20_deploy("TEST", "1000", None, None);
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
    assert!(json.contains(r#""op":"deploy""#));
    assert!(json.contains(r#""tick":"TEST""#));
    assert!(json.contains(r#""max":"1000""#));
}
