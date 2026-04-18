//! SPHINCSWallet integration test — Hybrid ECDSA + SLH-DSA-SHA2-128s contract.
//!
//! ## Security Model: Two-Layer Authentication
//!
//! This contract creates a quantum-resistant spending path by combining
//! classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
//!
//! 1. **ECDSA** proves the signature commits to this specific transaction
//!    (via OP_CHECKSIG over the sighash preimage).
//! 2. **SLH-DSA** proves the ECDSA signature was authorized by the SLH-DSA
//!    key holder — the ECDSA signature bytes ARE the message that SLH-DSA signs.
//!
//! A quantum attacker who can break ECDSA could forge a valid ECDSA
//! signature, but they cannot produce a valid SLH-DSA signature over their
//! forged sig without knowing the SLH-DSA secret key. SLH-DSA security
//! relies only on SHA-256 collision resistance, not on any number-theoretic
//! assumption vulnerable to Shor's algorithm.
//!
//! Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
//! can sign many messages — it's NIST FIPS 205 standardized.
//!
//! ## Constructor
//!   - ecdsaPubKeyHash: Addr — 20-byte HASH160 of compressed ECDSA public key
//!   - slhdsaPubKeyHash: ByteString — 20-byte HASH160 of 32-byte SLH-DSA public key
//!
//! ## Method: spend(slhdsaSig, slhdsaPubKey, sig, pubKey)
//!   - slhdsaSig: 7,856-byte SLH-DSA-SHA2-128s signature
//!   - slhdsaPubKey: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16])
//!   - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
//!   - pubKey: 33-byte compressed ECDSA public key
//!
//! ## Script Size
//!   ~188 KB — SLH-DSA verification requires computing multiple WOTS+
//!   verifications and Merkle tree path checks.
//!
//! ## Test Approach
//!   Deployment tests use hash commitments of test keys. Full spending tests
//!   require raw transaction construction (two-pass signing: ECDSA first, then
//!   SLH-DSA over the ECDSA sig). The Go integration suite (TestSLHDSA_ValidSpend)
//!   implements the complete two-pass spending flow.
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

/// Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16]).
/// Generated from seed [0, 1, 2, ..., 47] with SLH-DSA-SHA2-128s (n=16).
const SLHDSA_TEST_PK: &str = "00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf";

/// Compute HASH160 (RIPEMD160(SHA256(data))) and return as hex string.
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
fn test_sphincs_wallet_compile() {
    let artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts");
    assert_eq!(artifact.contract_name, "SPHINCSWallet");
    assert!(!artifact.script.is_empty());
}

#[test]
fn test_sphincs_wallet_script_size() {
    let artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts");
    let script_bytes = artifact.script.len() / 2;
    // SLH-DSA scripts are typically ~188 KB
    assert!(script_bytes > 100_000, "script too small: {} bytes", script_bytes);
    assert!(script_bytes < 500_000, "script too large: {} bytes", script_bytes);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_sphincs_wallet_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let slhdsa_pk_hash = hash160_hex(SLHDSA_TEST_PK);

    // Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(slhdsa_pk_hash),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_sphincs_wallet_deploy_different_key() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let other_pk = "aabbccdd00000000000000000000000011223344556677889900aabbccddeeff";
    let other_pk_hash = hash160_hex(other_pk);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(other_pk_hash),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

/// Deploy and verify UTXO exists (full spend requires raw tx construction).
///
/// The hybrid spend pattern requires:
///   1. Build unsigned spending transaction
///   2. ECDSA-sign the transaction input
///   3. SLH-DSA-sign the ECDSA signature bytes
///   4. Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>
///
/// This two-pass signing pattern is fully tested in the Go integration suite
/// (TestSLHDSA_ValidSpend) which uses raw transaction construction.
#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_sphincs_wallet_deploy_and_verify_utxo() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let slhdsa_pk_hash = hash160_hex(SLHDSA_TEST_PK);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(slhdsa_pk_hash),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);

    // Contract is deployed with correct hash commitments
    assert!(contract.get_utxo().is_some(), "expected UTXO after deploy");
}
