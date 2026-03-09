//! CovenantVault integration test — stateless contract with checkSig + checkPreimage.
//!
//! ## How It Works
//!
//! CovenantVault demonstrates a covenant pattern: it constrains HOW funds can be spent,
//! not just WHO can spend them. The contract checks:
//!   1. The owner's ECDSA signature (authentication via checkSig)
//!   2. The transaction preimage (via checkPreimage / OP_PUSH_TX)
//!   3. That the transaction outputs match the expected P2PKH script to the recipient
//!      with amount >= minAmount (enforced by comparing hash256(expectedOutput) against
//!      extractOutputHash(txPreimage))
//!
//! ### Constructor
//!   - owner: PubKey — the ECDSA public key that must sign to spend
//!   - recipient: Addr — the hash160 of the authorized recipient's public key
//!   - minAmount: bigint — minimum satoshis that must be sent to the recipient
//!
//! ### Method: spend(sig: Sig, txPreimage: SigHashPreimage)
//!   The compiler inserts an implicit _opPushTxSig parameter before the declared params.
//!   The full unlocking script order is: <opPushTxSig> <sig> <txPreimage>
//!
//! ### Spending Limitation
//!   Covenant spending requires constructing a transaction whose outputs exactly match
//!   what the contract expects (a P2PKH output to the recipient for minAmount satoshis).
//!   The SDK's generic call() creates default outputs that don't match. For real
//!   applications, developers use the SDK's raw transaction builder.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[ignore]
fn test_covenant_vault_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");
    assert_eq!(artifact.contract_name, "CovenantVault");
}

#[test]
#[ignore]
fn test_covenant_vault_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let recipient = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Constructor: (owner: PubKey, recipient: Addr, minAmount: bigint)
    // Addr is a pubKeyHash (20-byte hash160)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Bytes(recipient.pub_key_hash),
        SdkValue::Int(1000),
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
fn test_covenant_vault_deploy_zero_min_amount() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let recipient = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Bytes(recipient.pub_key_hash),
        SdkValue::Int(0),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[ignore]
fn test_covenant_vault_deploy_large_min_amount() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let recipient = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Bytes(recipient.pub_key_hash),
        SdkValue::Int(100_000_000), // 1 BTC in satoshis
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[ignore]
fn test_covenant_vault_deploy_same_key_owner_recipient() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");

    let mut provider = create_provider();
    let both = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(both.pub_key_hex),
        SdkValue::Bytes(both.pub_key_hash),
        SdkValue::Int(500),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

/// Spend with the wrong signer should be rejected (checkSig fails before covenant check).
#[test]
#[ignore]
fn test_covenant_vault_wrong_signer_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/covenant-vault/CovenantVault.runar.ts");

    let mut provider = create_provider();
    let recipient = create_wallet();

    // Deploy with owner=walletA
    let (owner_signer, owner_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Bytes(recipient.pub_key_hash),
        SdkValue::Int(1000),
    ]);

    contract
        .deploy(&mut provider, &*owner_signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call spend with walletB — checkSig will fail on-chain
    let (wrong_signer, _) = create_funded_wallet(&mut provider);
    let result = contract.call(
        "spend",
        &[SdkValue::Auto, SdkValue::Auto],
        &mut provider,
        &*wrong_signer,
        None,
    );
    assert!(result.is_err(), "spend with wrong signer should be rejected");
}
