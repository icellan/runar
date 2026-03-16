//! FunctionPatterns integration test — stateful contract demonstrating private methods,
//! built-in functions, and method composition (SDK Deploy path).
//!
//! All methods require a Sig parameter via requireOwner(sig), so spending requires
//! raw transaction construction. We test compile + deploy via the SDK.

use crate::helpers::*;
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, SdkValue};
use std::collections::HashMap;

#[test]
#[ignore]
fn test_function_patterns_compile() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");
    assert_eq!(artifact.contract_name, "FunctionPatterns");
}

#[test]
#[ignore]
fn test_function_patterns_deploy() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Constructor: (owner: PubKey, balance: bigint)
    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(1000),
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
fn test_function_patterns_deploy_zero_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(0),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[ignore]
fn test_function_patterns_deploy_large_balance() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");

    let mut provider = create_provider();
    let owner = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner.pub_key_hex),
        SdkValue::Int(999_999_999),
    ]);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
}

#[test]
#[ignore]
fn test_function_patterns_distinct_deploy_txids() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");

    let mut provider = create_provider();
    let owner1 = create_wallet();
    let owner2 = create_wallet();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let mut contract1 = RunarContract::new(artifact.clone(), vec![
        SdkValue::Bytes(owner1.pub_key_hex),
        SdkValue::Int(100),
    ]);
    let (txid1, _) = contract1
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy 1 failed");

    let mut contract2 = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner2.pub_key_hex),
        SdkValue::Int(200),
    ]);
    let (txid2, _) = contract2
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 10000,
            change_address: None,
        })
        .expect("deploy 2 failed");

    assert!(!txid1.is_empty());
    assert!(!txid2.is_empty());
    assert_ne!(txid1, txid2);
}

#[test]
#[ignore]
fn test_function_patterns_deposit() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(100),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    let (call_txid, _tx) = contract
        .call(
            "deposit",
            &[SdkValue::Auto, SdkValue::Int(50)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("deposit failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_function_patterns_deposit_then_withdraw() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");
    let mut provider = create_provider();
    let (signer, owner_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
    ]);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // deposit(sig, 500) -> balance = 1500
    contract
        .call(
            "deposit",
            &[SdkValue::Auto, SdkValue::Int(500)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("deposit failed");

    // withdraw(sig, 200, 100) -> fee = 200*100/10000 = 2, deduction = 202, balance = 1298
    contract
        .call(
            "withdraw",
            &[SdkValue::Auto, SdkValue::Int(200), SdkValue::Int(100)],
            &mut provider,
            &*signer,
            None,
        )
        .expect("withdraw failed");
}

#[test]
#[ignore]
fn test_function_patterns_wrong_owner_rejected() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/function-patterns/FunctionPatterns.runar.ts");
    let mut provider = create_provider();
    // Deploy with owner=walletA
    let (signer_a, owner_wallet) = create_funded_wallet(&mut provider);

    let mut contract = RunarContract::new(artifact, vec![
        SdkValue::Bytes(owner_wallet.pub_key_hex.clone()),
        SdkValue::Int(1000),
    ]);

    contract
        .deploy(&mut provider, &*signer_a, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Call deposit with a different signer — should be rejected
    let (signer_b, _wallet_b) = create_funded_wallet(&mut provider);
    let mut new_state = HashMap::new();
    new_state.insert("balance".to_string(), SdkValue::Int(1050));

    let result = contract.call(
        "deposit",
        &[SdkValue::Auto, SdkValue::Int(50)],
        &mut provider,
        &*signer_b,
        Some(&CallOptions {
            new_state: Some(new_state),
            ..Default::default()
        }),
    );
    assert!(result.is_err(), "deposit with wrong owner should be rejected");
}
