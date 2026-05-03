//! PrivateHelperOutputs integration test — 2026-04-30 audit regression
//! (F1 + F3).
//!
//! Gated with `regtest` feature; requires a local Bitcoin regtest node.
//! Mirrors the TS / Go integration tests for the same contract.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_private_helper_outputs_commit_chain() {
    skip_if_no_node();

    // Three sequential commits — each spends the previous
    // continuation UTXO. Failure here means the runtime hashOutputs
    // hash didn't match the compiled continuation, which is exactly
    // what F1's shallow-scan miss would produce for state-mutation
    // routed through a private helper.
    let artifact = compile_contract(
        "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts",
    );
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    for i in 0..3 {
        let (txid, _) = contract
            .call("commit", &[], &mut provider, &*signer, None)
            .unwrap_or_else(|e| panic!("commit #{} failed: {:?}", i + 1, e));
        assert!(!txid.is_empty(), "commit #{i}: empty txid");
    }
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_private_helper_outputs_log_emits_data() {
    skip_if_no_node();

    let artifact = compile_contract(
        "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts",
    );
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 5000,
            change_address: None,
        })
        .expect("deploy failed");

    // Hex literal: OP_RETURN-style data (0x6a) + 7-byte ASCII payload.
    let payload = SdkValue::Bytes("6a0768656c6c6f21".to_string());
    let (txid, _) = contract
        .call("log", &[payload], &mut provider, &*signer, None)
        .expect("log call failed");
    assert!(!txid.is_empty());
}
