//! Escrow integration test — stateless contract with dual-signature checkSig.
//!
//! Escrow locks funds and allows release or refund via two methods, each
//! requiring signatures from two parties (dual-sig):
//!   - release(sellerSig, arbiterSig) — seller + arbiter must both sign
//!   - refund(buyerSig, arbiterSig) — buyer + arbiter must both sign
//!
//! This ensures no party can act alone. The arbiter serves as the trust anchor.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[ignore]
fn test_escrow_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");
    assert_eq!(artifact.contract_name, "Escrow");
}

#[test]
#[ignore]
fn test_escrow_deploy_three_pubkeys() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let buyer = create_wallet();
    let seller = create_wallet();
    let arbiter = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Constructor: (buyer: PubKey, seller: PubKey, arbiter: PubKey)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(buyer.pub_key_hex),
        SdkValue::Bytes(seller.pub_key_hex),
        SdkValue::Bytes(arbiter.pub_key_hex),
    ]);

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
#[ignore]
fn test_escrow_deploy_same_key_multiple_roles() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let buyer_and_arbiter = create_wallet();
    let seller = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Same key as both buyer and arbiter
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(buyer_and_arbiter.pub_key_hex.clone()),
        SdkValue::Bytes(seller.pub_key_hex),
        SdkValue::Bytes(buyer_and_arbiter.pub_key_hex),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

/// release(sellerSig, arbiterSig) — method index 0
/// Uses the same key for both seller and arbiter roles so the SDK
/// auto-computes both signatures from the single signer.
#[test]
#[ignore]
fn test_escrow_release() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let buyer = create_wallet();
    // Use the funded signer as both seller and arbiter
    let (signer, signer_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(buyer.pub_key_hex),
        SdkValue::Bytes(signer_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(signer_wallet.pub_key_hex.clone()),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // release(sellerSig=Auto, arbiterSig=Auto) — both auto-computed from signer
    let (call_txid, _tx) = contract
        .call(
            "release",
            &[SdkValue::Auto, SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("release failed");
    assert!(!call_txid.is_empty());
    assert_eq!(call_txid.len(), 64);
}

/// refund(buyerSig, arbiterSig) — method index 1
/// Uses the same key for both buyer and arbiter roles.
#[test]
#[ignore]
fn test_escrow_refund() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let seller = create_wallet();
    // Use the funded signer as both buyer and arbiter
    let (signer, signer_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(signer_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(seller.pub_key_hex),
        SdkValue::Bytes(signer_wallet.pub_key_hex.clone()),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // refund(buyerSig=Auto, arbiterSig=Auto)
    let (call_txid, _tx) = contract
        .call(
            "refund",
            &[SdkValue::Auto, SdkValue::Auto],
            &mut provider,
            &*signer,
            None,
        )
        .expect("refund failed");
    assert!(!call_txid.is_empty());
    assert_eq!(call_txid.len(), 64);
}

#[test]
#[ignore]
fn test_escrow_release_wrong_signer_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let buyer = create_wallet();
    // Deploy with seller=arbiter=walletA
    let (signer_a, wallet_a) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(buyer.pub_key_hex),
        SdkValue::Bytes(wallet_a.pub_key_hex.clone()),
        SdkValue::Bytes(wallet_a.pub_key_hex.clone()),
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call release with walletB — checkSig should fail
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "release",
        &[SdkValue::Auto, SdkValue::Auto],
        &mut provider,
        &*signer_b,
        None,
    );
    assert!(result.is_err(), "release with wrong signer should be rejected");
}

#[test]
#[ignore]
fn test_escrow_refund_wrong_signer_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/escrow/Escrow.runar.ts");

    let mut provider = create_provider();
    let seller = create_wallet();
    // Deploy with buyer=arbiter=walletA
    let (signer_a, wallet_a) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(wallet_a.pub_key_hex.clone()),
        SdkValue::Bytes(seller.pub_key_hex),
        SdkValue::Bytes(wallet_a.pub_key_hex.clone()),
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call refund with walletB — checkSig should fail
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "refund",
        &[SdkValue::Auto, SdkValue::Auto],
        &mut provider,
        &*signer_b,
        None,
    );
    assert!(result.is_err(), "refund with wrong signer should be rejected");
}
