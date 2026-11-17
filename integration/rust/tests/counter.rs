//! Counter integration test — stateful contract (SDK Deploy/Call path).
//!
//! **Gating**: all on-chain tests are gated with
//! `#[cfg_attr(not(feature = "regtest"), ignore)]`. They require a local Bitcoin
//! regtest node (see `integration/rust/README.md`). Run with:
//!     cargo test --features regtest
//! Tests without the gate (pure compile/script-size checks) run by default.

use crate::helpers::*;
use runar_lang::sdk::{CallOptions, DeployOptions, RunarContract, SdkValue};
use std::collections::HashMap;

/// Read the `count` field back out of the state section of `contract`'s
/// CURRENT on-chain UTXO -- the real bytes the node just accepted -- and
/// compare it to `want`. Deliberately independent of `contract.state()`; see
/// `helpers::read_on_chain_state`'s doc comment for why.
fn assert_on_chain_count(
    provider: &dyn runar_lang::sdk::Provider,
    artifact: &runar_lang::sdk::RunarArtifact,
    contract: &RunarContract,
    want: i64,
) {
    let utxo = contract
        .get_utxo()
        .expect("assert_on_chain_count: no current UTXO tracked on the contract");
    let state = read_on_chain_state(provider, artifact, utxo);
    let got = state.get("count").unwrap_or_else(|| {
        panic!("assert_on_chain_count: on-chain state has no 'count' field; got {:?}", state)
    });
    assert_eq!(
        got,
        &SdkValue::Int(want),
        "on-chain state.count (tx {} output {})",
        utxo.txid,
        utxo.output_index,
    );
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_counter_increment() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact.clone(), vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
            ..Default::default()
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

    // increment: count 0 -> 1. Read the value back out of the ACTUAL output
    // script the node accepted, not the SDK's predicted next state.
    assert_on_chain_count(&provider, &artifact, &contract, 1);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_counter_chain() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact.clone(), vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
            ..Default::default()
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
    assert_on_chain_count(&provider, &artifact, &contract, 1);

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
    assert_on_chain_count(&provider, &artifact, &contract, 2);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_counter_decrement() {
    skip_if_no_node();

    let artifact = compile_contract("examples/ts/stateful-counter/Counter.runar.ts");
    let mut contract = RunarContract::new(artifact.clone(), vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
            ..Default::default()
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
    assert_on_chain_count(&provider, &artifact, &contract, 1);

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
    assert_on_chain_count(&provider, &artifact, &contract, 0);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
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
            ..Default::default()
        })
        .expect("deploy failed");

    // Claim count=99 instead of 1 — hashOutputs mismatch
    let mut wrong_state = HashMap::new();
    wrong_state.insert("count".to_string(), SdkValue::Int(99));

    let probe = provider.rejection_probe();
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
    assert_node_rejected(&provider, probe, result, SCRIPT_VERIFY_FAILED);
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
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
            ..Default::default()
        })
        .expect("deploy failed");

    // count=0, decrement -> assert(count > 0) fails
    let mut bad_state = HashMap::new();
    bad_state.insert("count".to_string(), SdkValue::Int(-1));

    let probe = provider.rejection_probe();
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
    assert_node_rejected(&provider, probe, result, SCRIPT_VERIFY_FAILED);
}
