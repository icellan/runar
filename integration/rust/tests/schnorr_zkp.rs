//! SchnorrZKP integration test — stateless contract with EC scalar math verification.
//!
//! ## How It Works
//!
//! SchnorrZKP implements a Schnorr zero-knowledge proof verifier on-chain.
//! The contract locks funds to an EC public key P, and spending requires proving
//! knowledge of the discrete logarithm k (i.e., P = k*G) without revealing k.
//!
//! The challenge e is derived on-chain via the Fiat-Shamir heuristic:
//!     e = bin2num(hash256(cat(rPoint, pubKey)))
//!
//! This makes the proof non-interactive and prevents the prover from choosing
//! a convenient challenge.
//!
//! ### Constructor
//!   - pubKey: Point — the EC public key (64-byte uncompressed x[32] || y[32])
//!
//! ### Method: verify(rPoint: Point, s: bigint)
//!   The prover generates a proof:
//!     1. Pick random nonce r, compute R = r*G (commitment)
//!     2. e is derived on-chain: e = bin2num(hash256(R || P))
//!     3. Compute s = r + e*k (mod n) (response)
//!   The contract checks: s*G === R + e*P (Schnorr verification equation)
//!
//! ### Script Size
//!   ~877 KB — dominated by EC scalar multiplication codegen.
//!
//! ### Important Notes
//!   - No Sig param — pure mathematical proof, not ECDSA
//!   - s is a 256-bit scalar, passed as SdkValue::Bytes (script number hex)
//!     since SdkValue::Int only supports i64
//!   - Uses k256 crate for EC arithmetic in the test helper

use crate::helpers::*;
use crate::helpers::crypto::{ec_mul_gen_point, generate_schnorr_proof_fs};
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[ignore]
fn test_schnorr_zkp_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");
    assert_eq!(artifact.contract_name, "SchnorrZKP");
    assert!(!artifact.script.is_empty());
}

#[test]
#[ignore]
fn test_schnorr_zkp_script_size() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");
    let script_bytes = artifact.script.len() / 2;
    // EC-heavy scripts are typically ~877 KB
    assert!(script_bytes > 100_000, "script too small: {} bytes", script_bytes);
    assert!(script_bytes < 2_000_000, "script too large: {} bytes", script_bytes);
}

#[test]
#[ignore]
fn test_schnorr_zkp_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Generate a keypair: k is private, P = k*G is the public key point
    let pub_key_hex = ec_mul_gen_point(42);

    // Constructor: (pubKey: Point) — 64-byte hex (x[32] || y[32])
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(pub_key_hex),
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
#[ignore]
fn test_schnorr_zkp_deploy_different_key() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let pub_key_hex = ec_mul_gen_point(123456789);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(pub_key_hex),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

/// Deploy and spend with a valid Schnorr ZKP proof using Fiat-Shamir challenge.
///
/// The proof satisfies the Schnorr verification equation s*G = R + e*P:
///   1. Private key k=42, public key P = k*G
///   2. Nonce r=7777, commitment R = r*G
///   3. Challenge e = bin2num(hash256(R || P)) (Fiat-Shamir, derived on-chain)
///   4. Response s = r + e*k mod n
///   5. Call verify(R, s) — the contract derives e and verifies s*G === R + e*P
#[test]
#[ignore]
fn test_schnorr_zkp_spend_valid_proof() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Generate proof with Fiat-Shamir: k=42 (private key), r=7777 (nonce)
    // e is derived from hash256(R || P), s = r + e*k mod n
    let (pub_key_hex, r_point_hex, s_script_hex) = generate_schnorr_proof_fs(42, 7777);

    // Deploy with the public key P
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(pub_key_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");

    // Spend by calling verify(rPoint, s)
    // s is a 256-bit scalar — use SdkValue::Bytes with script number encoding
    let (spend_txid, _tx) = contract
        .call(
            "verify",
            &[
                SdkValue::Bytes(r_point_hex),   // R point (64-byte hex)
                SdkValue::Bytes(s_script_hex),  // s as LE signed-magnitude script number
            ],
            &mut provider,
            &*signer,
            None,
        )
        .expect("spend failed");
    assert!(!spend_txid.is_empty());
    assert_eq!(spend_txid.len(), 64);
}

#[test]
#[ignore]
fn test_schnorr_zkp_invalid_s_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/schnorr-zkp/SchnorrZKP.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Generate valid proof, then tamper with s
    let (pub_key_hex, r_point_hex, _s_script_hex) = generate_schnorr_proof_fs(42, 7777);

    // Deploy with the public key P
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(pub_key_hex),
    ]);
    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 50000,
            change_address: None,
        })
        .expect("deploy failed");

    // Tamper: use a completely wrong s value
    let tampered_s = "0100".to_string(); // s=1 (very wrong)

    let result = contract.call(
        "verify",
        &[
            SdkValue::Bytes(r_point_hex),
            SdkValue::Bytes(tampered_s),
        ],
        &mut provider,
        &*signer,
        None,
    );
    assert!(result.is_err(), "verify with tampered s should be rejected");
}
