#[path = "OrdinalNFT.runar.rs"]
mod contract;

use contract::*;
use runar::prelude::*;
use runar::sdk::{
    ordinals::{
        build_inscription_envelope, parse_inscription_envelope, Inscription,
    },
    RunarArtifact, RunarContract, SdkValue, Utxo,
};
use runar_compiler_rust::compile_from_source_str;

const SOURCE: &str = include_str!("OrdinalNFT.runar.rs");

/// Compile the contract source and deserialize into the SDK's RunarArtifact.
fn compile_artifact() -> RunarArtifact {
    let compiler_artifact = compile_from_source_str(SOURCE, Some("OrdinalNFT.runar.rs"))
        .expect("OrdinalNFT must compile");
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
    let c = OrdinalNFT { pub_key_hash: hash160(&pk) };
    c.unlock(&ALICE.sign_test_message(), &pk);
}

#[test]
#[should_panic]
fn test_unlock_rejects_wrong_key() {
    let pk = ALICE.pub_key.to_vec();
    let wrong_pk = BOB.pub_key.to_vec();
    let c = OrdinalNFT { pub_key_hash: hash160(&pk) };
    c.unlock(&BOB.sign_test_message(), &wrong_pk);
}

// ---------------------------------------------------------------------------
// Compile check
// ---------------------------------------------------------------------------

#[test]
fn test_compile() {
    runar::compile_check(SOURCE, "OrdinalNFT.runar.rs").unwrap();
}

#[test]
fn test_compiles_to_artifact() {
    let artifact = compile_artifact();
    assert_eq!(artifact.contract_name, "OrdinalNFT");
    assert_eq!(artifact.abi.methods.len(), 1);
    assert_eq!(artifact.abi.methods[0].name, "unlock");
}

// ---------------------------------------------------------------------------
// SDK inscription flow
// ---------------------------------------------------------------------------

#[test]
fn test_attaches_png_inscription_to_locking_script() {
    let artifact = compile_artifact();
    let mut contract = RunarContract::new(artifact, constructor_args());

    let png_data = "89504e470d0a1a0a";
    contract.with_inscription(Inscription {
        content_type: "image/png".to_string(),
        data: png_data.to_string(),
    });

    let locking_script = contract.get_locking_script();
    let expected_envelope = build_inscription_envelope("image/png", png_data);
    assert!(locking_script.contains(&expected_envelope));

    let parsed = parse_inscription_envelope(&locking_script)
        .expect("envelope must parse from locking script");
    assert_eq!(parsed.content_type, "image/png");
    assert_eq!(parsed.data, png_data);
}

#[test]
fn test_attaches_text_inscription_to_locking_script() {
    let artifact = compile_artifact();
    let mut contract = RunarContract::new(artifact, constructor_args());

    // "Hello, Ordinals!" as hex
    let text_data = "48656c6c6f2c204f7264696e616c7321";
    contract.with_inscription(Inscription {
        content_type: "text/plain".to_string(),
        data: text_data.to_string(),
    });

    let locking_script = contract.get_locking_script();
    let parsed = parse_inscription_envelope(&locking_script).unwrap();
    assert_eq!(parsed.content_type, "text/plain");
    assert_eq!(parsed.data, text_data);
}

#[test]
fn test_inscription_survives_from_utxo_round_trip() {
    let artifact = compile_artifact();
    let mut contract = RunarContract::new(artifact.clone(), constructor_args());

    let png_data = "89504e470d0a1a0a";
    contract.with_inscription(Inscription {
        content_type: "image/png".to_string(),
        data: png_data.to_string(),
    });

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
    assert_eq!(insc.content_type, "image/png");
    assert_eq!(insc.data, png_data);
}

#[test]
fn test_locking_script_without_inscription_has_no_envelope() {
    let artifact = compile_artifact();
    let contract = RunarContract::new(artifact, constructor_args());

    let locking_script = contract.get_locking_script();
    assert!(parse_inscription_envelope(&locking_script).is_none());
}
