//! P-384 (NIST P-384 / secp384r1) wallet integration test — hybrid ECDSA +
//! P-384 contract.
//!
//! Mirrors the P-256 pattern (`p256_wallet.rs`). The P384Wallet contract
//! requires both an ECDSA secp256k1 signature and a P-384 signature over
//! the ECDSA sig bytes; full spend tests need a two-pass flow, so this
//! suite covers compile + script-size + deploy.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

const SOURCE_PATH: &str = "examples/ts/p384-wallet/P384Wallet.runar.ts";

fn hash160_hex(hex_data: &str) -> String {
    let bytes: Vec<u8> = (0..hex_data.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_data[i..i + 2], 16).unwrap())
        .collect();
    let sha = Sha256::digest(&bytes);
    let ripe = Ripemd160::digest(sha);
    ripe.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_p384_wallet_compile() {
    let artifact = compile_contract(SOURCE_PATH);
    assert_eq!(artifact.contract_name, "P384Wallet");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_p384_wallet_script_size() {
    let artifact = compile_contract(SOURCE_PATH);
    let script_bytes = artifact.script.len() / 2;
    // P-384 verification is heavyweight; expect a substantial script (typically
    // larger than P-256 because the field is 48 bytes wide).
    assert!(
        script_bytes > 5_000,
        "P-384 wallet script too small: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p384_wallet_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(SOURCE_PATH);

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    // Deterministic 49-byte P-384 compressed pub key (02 || 48-byte x).
    let p384_pk = format!("02{}", "cd".repeat(48));
    let p384_pk_hash = hash160_hex(&p384_pk);

    let mut contract = RunarContract::new(
        artifact,
        vec![
            SdkValue::Bytes(wallet.pub_key_hash.clone()),
            SdkValue::Bytes(p384_pk_hash),
        ],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        })
        .expect("P-384 wallet deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
