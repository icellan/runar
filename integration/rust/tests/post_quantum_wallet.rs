//! PostQuantumWallet integration test — Hybrid ECDSA + WOTS+ contract.
//!
//! ## Security Model: Two-Layer Authentication
//!
//! This contract creates a quantum-resistant spending path by combining
//! classical ECDSA with WOTS+ (Winternitz One-Time Signature):
//!
//! 1. **ECDSA** proves the signature commits to this specific transaction
//!    (via OP_CHECKSIG over the sighash preimage).
//! 2. **WOTS+** proves the ECDSA signature was authorized by the WOTS key
//!    holder — the ECDSA signature bytes ARE the message that WOTS signs.
//!
//! A quantum attacker who can break ECDSA could forge a valid ECDSA
//! signature, but they cannot produce a valid WOTS+ signature over their
//! forged sig without knowing the WOTS secret key.
//!
//! ## Constructor
//!   - ecdsaPubKeyHash: Addr — 20-byte HASH160 of compressed ECDSA public key
//!   - wotsPubKeyHash: ByteString — 20-byte HASH160 of 64-byte WOTS+ public key
//!
//! ## Method: spend(wotsSig, wotsPubKey, sig, pubKey)
//!   - wotsSig: 2,144-byte WOTS+ signature (67 chains x 32 bytes)
//!   - wotsPubKey: 64-byte WOTS+ public key (pubSeed[32] || pkRoot[32])
//!   - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
//!   - pubKey: 33-byte compressed ECDSA public key
//!
//! ## Script Size
//!   ~10 KB — modest because WOTS+ verification is iterative SHA-256 hashing.
//!
//! ## Test Approach
//!   Deployment tests use hash commitments of test keys. Full spending tests
//!   require raw transaction construction (two-pass signing: ECDSA first, then
//!   WOTS over the ECDSA sig). The Go integration suite (TestWOTS_ValidSpend)
//!   implements the complete two-pass spending flow.

use crate::helpers::*;
use crate::helpers::crypto::{wots_keygen, wots_pub_key_hex};
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;

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
#[ignore]
fn test_post_quantum_wallet_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts");
    assert_eq!(artifact.contract_name, "PostQuantumWallet");
    assert!(!artifact.script.is_empty());
}

#[test]
#[ignore]
fn test_post_quantum_wallet_script_size() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts");
    let script_bytes = artifact.script.len() / 2;
    // WOTS+ scripts are typically ~10 KB
    assert!(script_bytes > 5000, "script too small: {} bytes", script_bytes);
    assert!(script_bytes < 50000, "script too large: {} bytes", script_bytes);
}

#[test]
#[ignore]
fn test_post_quantum_wallet_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    // Generate WOTS+ keypair from a deterministic seed
    let mut seed = vec![0u8; 32];
    seed[0] = 0x42;
    let mut pub_seed = vec![0u8; 32];
    pub_seed[0] = 0x01;
    let kp = wots_keygen(&seed, &pub_seed);

    // Hash160 of the WOTS+ public key
    let wots_pk_hash = hash160_hex(&wots_pub_key_hex(&kp));

    // Constructor: (ecdsaPubKeyHash, wotsPubKeyHash)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(wots_pk_hash),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

#[test]
#[ignore]
fn test_post_quantum_wallet_deploy_different_seed() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let mut seed = vec![0u8; 32];
    seed[0] = 0x99;
    seed[1] = 0xAB;
    let mut pub_seed = vec![0u8; 32];
    pub_seed[0] = 0x02;
    let kp = wots_keygen(&seed, &pub_seed);

    let wots_pk_hash = hash160_hex(&wots_pub_key_hex(&kp));

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(wots_pk_hash),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
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
///   3. WOTS-sign the ECDSA signature bytes
///   4. Construct unlocking script: <wotsSig> <wotsPK> <ecdsaSig> <ecdsaPubKey>
///
/// This two-pass signing pattern is fully tested in the Go integration suite
/// (TestWOTS_ValidSpend) which uses raw transaction construction.
#[test]
#[ignore]
fn test_post_quantum_wallet_deploy_and_verify_utxo() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/post-quantum-wallet/PostQuantumWallet.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    // Generate WOTS+ keypair
    let mut seed = vec![0u8; 32];
    seed[0] = 0x42;
    let mut pub_seed = vec![0u8; 32];
    pub_seed[0] = 0x01;
    let kp = wots_keygen(&seed, &pub_seed);

    let wots_pk_hash = hash160_hex(&wots_pub_key_hex(&kp));

    // Deploy
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet.pub_key_hash.clone()),
        SdkValue::Bytes(wots_pk_hash),
    ]);
    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);

    // Contract is deployed with correct hash commitments
    assert!(contract.get_utxo().is_some(), "expected UTXO after deploy");
}
