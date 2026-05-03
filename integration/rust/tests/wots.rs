//! WOTS+ (Winternitz One-Time Signature) integration test — naive-INSECURE
//! example that wires `verifyWOTS` directly without an ECDSA co-signature
//! wrapper.
//!
//! The hybrid ECDSA + WOTS+ wallet is covered separately by
//! `post_quantum_wallet.rs`. This test covers the bare WOTS+ verification
//! primitive — script compiles, has plausible size (~10 KB), and deploys
//! on regtest.
//!
//! Mirrors `integration/go/wots_test.go`.

use crate::helpers::*;
use crate::helpers::crypto::{wots_keygen, wots_pub_key_hex};
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

const NAIVE_SOURCE_PATH: &str =
    "examples/ts/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.runar.ts";

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
fn test_wots_naive_compile() {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    assert!(!artifact.script.is_empty());
    assert!(!artifact.contract_name.is_empty());
}

#[test]
fn test_wots_naive_script_size() {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    let script_bytes = artifact.script.len() / 2;
    // WOTS+ scripts are typically ~10 KB.
    assert!(
        script_bytes > 5_000,
        "WOTS+ naive script too small: {} bytes",
        script_bytes
    );
    assert!(
        script_bytes < 50_000,
        "WOTS+ naive script too large: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_wots_naive_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(NAIVE_SOURCE_PATH);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Generate a WOTS+ keypair deterministically.
    let mut seed = vec![0u8; 32];
    seed[0] = 0x42;
    let mut pub_seed = vec![0u8; 32];
    pub_seed[0] = 0x01;
    let kp = wots_keygen(&seed, &pub_seed);
    let pk_hash = hash160_hex(&wots_pub_key_hex(&kp));

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(pk_hash)],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10_000,
            change_address: None,
        })
        .expect("WOTS+ naive deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
