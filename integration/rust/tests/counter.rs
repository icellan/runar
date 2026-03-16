//! Counter integration test — stateful contract (SDK Deploy/Call path).

use crate::helpers::*;
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, SdkValue};
use std::collections::HashMap;

#[test]
#[ignore]
fn test_counter_increment() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);

    let (call_txid, _tx) = contract
        .call(
            "increment",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call increment failed");
    assert!(!call_txid.is_empty());
}

#[test]
#[ignore]
fn test_counter_chain() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 0 -> 1
    contract
        .call(
            "increment",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call increment 0->1 failed");

    // 1 -> 2
    contract
        .call(
            "increment",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call increment 1->2 failed");
}

#[test]
#[ignore]
fn test_counter_decrement() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // 0 -> 1
    contract
        .call(
            "increment",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call increment failed");

    // 1 -> 0
    contract
        .call(
            "decrement",
            &[],
            &mut provider,
            &*signer,
            None,
        )
        .expect("call decrement failed");
}

#[test]
#[ignore]
fn test_counter_wrong_state() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Claim count=99 instead of 1 — hashOutputs mismatch
    let mut wrong_state = HashMap::new();
    wrong_state.insert("count".to_string(), SdkValue::Int(99));

    let result = contract.call(
        "increment",
        &[],
        &mut provider,
        &*signer,
        Some(&CallOptions {
            new_state: Some(wrong_state),
            ..Default::default()
        }),
    );
    assert!(result.is_err(), "expected wrong state to fail");
}

#[test]
#[ignore]
fn test_counter_underflow() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // count=0, decrement -> assert(count > 0) fails
    let mut bad_state = HashMap::new();
    bad_state.insert("count".to_string(), SdkValue::Int(-1));

    let result = contract.call(
        "decrement",
        &[],
        &mut provider,
        &*signer,
        Some(&CallOptions {
            new_state: Some(bad_state),
            ..Default::default()
        }),
    );
    assert!(result.is_err(), "expected underflow to fail");
}
