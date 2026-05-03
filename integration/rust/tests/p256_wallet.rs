//! P-256 (NIST P-256 / secp256r1) wallet integration test — hybrid ECDSA +
//! P-256 contract.
//!
//! Mirrors `integration/go/p256_wallet_test.go` and the SPHINCSWallet pattern.
//! The P256Wallet contract requires both an ECDSA secp256k1 signature
//! (commit-to-tx via OP_CHECKSIG) and a P-256 signature over the ECDSA sig
//! bytes — full spend tests would need a two-pass signing flow, so this
//! suite covers compile + script-size + deploy.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

const SOURCE_PATH: &str = "examples/ts/p256-wallet/P256Wallet.runar.ts";

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
fn test_p256_wallet_compile() {
    let artifact = compile_contract(SOURCE_PATH);
    assert_eq!(artifact.contract_name, "P256Wallet");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_p256_wallet_script_size() {
    let artifact = compile_contract(SOURCE_PATH);
    let script_bytes = artifact.script.len() / 2;
    // P-256 verification is heavyweight; expect a substantial script.
    assert!(
        script_bytes > 5_000,
        "P-256 wallet script too small: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p256_wallet_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(SOURCE_PATH);

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    // Deterministic 33-byte P-256 compressed pub key (02 || 32-byte x).
    let p256_pk = format!("02{}", "ab".repeat(32));
    let p256_pk_hash = hash160_hex(&p256_pk);

    let mut contract = RunarContract::new(
        artifact,
        vec![
            SdkValue::Bytes(wallet.pub_key_hash.clone()),
            SdkValue::Bytes(p256_pk_hash),
        ],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        })
        .expect("P-256 wallet deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
