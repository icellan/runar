//! WOTS+ (Winternitz One-Time Signature) integration test — naive-INSECURE
//! example that wires `verifyWOTS` directly without an ECDSA co-signature
//! wrapper.
//!
//! The hybrid ECDSA + WOTS+ wallet is covered separately by
//! `post_quantum_wallet.rs`. This test covers the bare WOTS+ verification
//! primitive — script compiles, has plausible size (~10 KB), a valid
//! signature unlocks it and a tampered one does not (offline in the strict
//! ScriptVm, and on regtest).
//!
//! The contract stores the 64-byte WOTS+ public key (pubSeed || pkRoot) and
//! calls `verifyWOTS(msg, sig, this.pubkey)` directly — there is no hash160
//! step, so the constructor argument is the RAW public key (GK-GAP-007: this
//! file used to pass hash160(pk), deploying a UTXO no valid signature could
//! unlock, and stayed green only because it never spent). Mirrors the spend
//! leg of `integration/zig/src/wots_test.zig`.

use crate::helpers::*;
use crate::helpers::crypto::{wots_keygen, wots_pub_key_hex, wots_sign, WotsKeyPair};
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, ScriptVm, SdkValue, VmOptions};

const NAIVE_SOURCE_PATH: &str =
    "examples/ts/post-quantum-wots-naive-INSECURE/PostQuantumWOTSNaiveInsecure.runar.ts";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn naive_keypair() -> WotsKeyPair {
    let mut seed = vec![0u8; 32];
    seed[0] = 0x42;
    let mut pub_seed = vec![0u8; 32];
    pub_seed[0] = 0x01;
    wots_keygen(&seed, &pub_seed)
}

/// The constructor argument the naive contract is deployed with. Shared by the
/// offline script check and the regtest legs so they test the same bytes.
fn naive_constructor_args(kp: &WotsKeyPair) -> Vec<SdkValue> {
    vec![SdkValue::Bytes(wots_pub_key_hex(kp))]
}

const NAIVE_MSG: &[u8] = b"runar wots naive integration";

/// (msg_hex, sig_hex) for NAIVE_MSG; `tamper` flips one signature byte.
fn naive_spend_args(kp: &WotsKeyPair, tamper: bool) -> Vec<SdkValue> {
    let mut sig = wots_sign(NAIVE_MSG, &kp.sk, &kp.pub_seed);
    if tamper {
        sig[0] ^= 0x01;
    }
    vec![SdkValue::Bytes(to_hex(NAIVE_MSG)), SdkValue::Bytes(to_hex(&sig))]
}

fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}

/// Run `spend(args)` against the deployed locking script in the strict
/// (consensus) ScriptVm. No node needed.
fn run_spend_offline(kp: &WotsKeyPair, tamper: bool) -> runar_lang::sdk::VmResult {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    let contract = RunarContract::new(artifact, naive_constructor_args(kp));
    let locking = contract.get_locking_script();
    let unlocking = contract
        .build_unlocking_script("spend", &naive_spend_args(kp, tamper))
        .expect("build unlocking script");
    ScriptVm::new(VmOptions::default()).execute(&hex_bytes(&unlocking), &hex_bytes(&locking))
}

/// GK-GAP-007: a valid WOTS+ signature must unlock the UTXO the deploy leg
/// creates. With hash160(pk) as the constructor argument it cannot.
#[test]
fn test_wots_naive_valid_sig_unlocks_offline() {
    let r = run_spend_offline(&naive_keypair(), false);
    assert!(r.success, "valid WOTS+ spend rejected by the script: {:?}", r.error);
}

/// Control: the same script must reject a tampered signature, so the
/// acceptance above is not a script that accepts everything.
#[test]
fn test_wots_naive_tampered_sig_rejected_offline() {
    let r = run_spend_offline(&naive_keypair(), true);
    assert!(!r.success, "tampered WOTS+ signature was accepted by the script");
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

/// Deploy a naive WOTS+ contract on regtest and return it.
fn deploy_naive(
    provider: &mut LoggingRPCProvider,
    signer: &dyn runar_lang::sdk::Signer,
    kp: &WotsKeyPair,
) -> RunarContract {
    let artifact = compile_contract(NAIVE_SOURCE_PATH);
    let mut contract = RunarContract::new(artifact, naive_constructor_args(kp));
    let (deploy_txid, _tx) = contract
        .deploy(provider, signer, &DeployOptions {
            satoshis: 10_000,
            change_address: None,
            ..Default::default()
        })
        .expect("WOTS+ naive deploy failed");
    assert_eq!(deploy_txid.len(), 64);
    contract
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_wots_naive_deploy_and_spend() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);
    let kp = naive_keypair();
    let mut contract = deploy_naive(&mut provider, &*signer, &kp);

    let (call_txid, _tx) = contract
        .call("spend", &naive_spend_args(&kp, false), &mut provider, &*signer, None::<&CallOptions>)
        .expect("valid WOTS+ spend rejected");
    assert_eq!(call_txid.len(), 64);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_wots_naive_tampered_sig_rejected() {
    skip_if_no_node();

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);
    let kp = naive_keypair();
    let mut contract = deploy_naive(&mut provider, &*signer, &kp);

    let before = provider.broadcast_attempts;
    let err = contract
        .call("spend", &naive_spend_args(&kp, true), &mut provider, &*signer, None::<&CallOptions>)
        .expect_err("tampered WOTS+ signature was accepted");
    // The attack tx must have reached the node and been refused by consensus,
    // not failed inside the SDK before broadcast.
    assert!(
        provider.broadcast_attempts > before,
        "tampered spend never reached the node (SDK-side failure): {}",
        err
    );
    assert!(
        err.contains("mandatory-script-verify-flag-failed"),
        "expected a node script-verify rejection, got: {}",
        err
    );
}
