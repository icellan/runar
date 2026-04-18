//! P2PKH integration test — stateless contract with checkSig.
//!
//! P2PKH locks funds to a public key hash. Spending requires a valid
//! signature and the matching public key. The SDK auto-computes Sig params
//! when SdkValue::Auto is passed.
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p2pkh_compile_and_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts");
    assert_eq!(artifact.contract_name, "P2PKH");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    // Constructor takes pubKeyHash (Addr = ByteString = hex string)
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Bytes(wallet.pub_key_hash.clone())]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p2pkh_deploy_and_spend() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts");

    let mut provider = create_provider();
    let (signer, wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(wallet.pub_key_hash.clone())],
    );

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Auto Sig and PubKey args are auto-computed by the SDK
    let (call_txid, _tx) = contract
        .call(
            "unlock",
            &[SdkValue::Auto, SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("spend failed");
    assert!(!call_txid.is_empty());
    assert_eq!(call_txid.len(), 64);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p2pkh_deploy_different_pubkeyhash() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts");

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Use a separate wallet's pubKeyHash as the lock target
    let other_wallet = create_wallet();
    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(other_wallet.pub_key_hash)],
    );

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_p2pkh_wrong_signer_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/p2pkh/P2PKH.runar.ts");

    let mut provider = create_provider();
    // Deploy locked to walletA's pubKeyHash
    let (signer_a, wallet_a) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(
        artifact,
        vec![SdkValue::Bytes(wallet_a.pub_key_hash.clone())],
    );

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call unlock with a different signer — should be rejected
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "unlock",
        &[SdkValue::Auto, SdkValue::Auto],
        &mut provider,
        &*signer_b,
        None,
    );
    assert!(result.is_err(), "unlock with wrong signer should be rejected");
}
