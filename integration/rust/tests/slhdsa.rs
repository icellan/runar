//! SLH-DSA (FIPS 205, SPHINCS+) integration test — naive-INSECURE example
//! contract that wires `verifySLHDSA_SHA2_128s` directly without an ECDSA
//! co-signature wrapper.
//!
//! The hybrid ECDSA + SLH-DSA wallet is covered separately by
//! `sphincs_wallet.rs`. This test covers the bare SLH-DSA verification
//! primitive surface — making sure the script compiles, has plausible
//! size for SLH-DSA-SHA2-128s (~188 KB), and deploys on regtest.
//!
//! Mirrors `integration/go/slhdsa_test.go`.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

const NAIVE_SOURCE_PATH: &str =
    "examples/ts/post-quantum-slhdsa-naive-INSECURE/PostQuantumSLHDSANaiveInsecure.runar.ts";

#[test]
fn test_slhdsa_naive_compile() {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    assert!(!artifact.script.is_empty());
    assert!(!artifact.contract_name.is_empty());
}

#[test]
fn test_slhdsa_naive_script_size() {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    let script_bytes = artifact.script.len() / 2;
    // SLH-DSA-SHA2-128s scripts are large (>= ~100 KB).
    assert!(
        script_bytes > 50_000,
        "SLH-DSA naive script too small: {} bytes",
        script_bytes
    );
    assert!(
        script_bytes < 500_000,
        "SLH-DSA naive script too large: {} bytes",
        script_bytes
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_slhdsa_naive_deploy() {
    skip_if_no_node();

    let artifact = compile_contract(NAIVE_SOURCE_PATH);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Constructor: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16]).
    // Use a deterministic test key. Full sign+verify spend tests are gated
    // on raw transaction construction (see Go's TestSLHDSA_ValidSpend).
    let pk = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";
    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(pk.to_string())],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50_000,
            change_address: None,
        })
        .expect("SLH-DSA naive deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
