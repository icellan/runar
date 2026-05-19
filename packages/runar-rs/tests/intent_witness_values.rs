//! R-6 — SDK consumer support for intent-intrinsic auto-injected witness params
//! (`_prevOutScript_<i>`, `_serialisedOutputs`).
//!
//! Covers:
//!   - filter: auto-injected witness params are NOT part of the user arg count
//!   - setters: set_prev_out_script / set_serialised_outputs store witness bytes
//!   - errors: missing witness raises a typed WitnessValueMissingError
//!   - wiring: witness bytes are appended to the primary unlocking script in
//!     ABI order (`_prevOutScript_*` first, then `_serialisedOutputs`)

use std::collections::HashMap;

use runar_lang::sdk::{
    CallOptions, DeployOptions, MockProvider, MockSigner, RunarContract, SdkValue, Signer, Utxo,
};
use runar_lang::sdk::errors::WitnessValueMissingError;
use runar_lang::sdk::types::{Abi, AbiConstructor, AbiMethod, AbiParam, RunarArtifact, StateField};

fn make_intent_artifact(prev_out_inputs: &[usize], serialised: bool) -> RunarArtifact {
    let mut params: Vec<AbiParam> = vec![
        // One ordinary user param
        AbiParam { name: "amount".into(), param_type: "bigint".into(), fixed_array: None },
        // Compiler-injected continuation params for stateful methods
        AbiParam { name: "_changePKH".into(), param_type: "Ripemd160".into(), fixed_array: None },
        AbiParam { name: "_changeAmount".into(), param_type: "bigint".into(), fixed_array: None },
        AbiParam { name: "_newAmount".into(), param_type: "bigint".into(), fixed_array: None },
        AbiParam { name: "txPreimage".into(), param_type: "SigHashPreimage".into(), fixed_array: None },
    ];
    for &i in prev_out_inputs {
        params.push(AbiParam {
            name: format!("_prevOutScript_{}", i),
            param_type: "ByteString".into(),
            fixed_array: None,
        });
    }
    if serialised {
        params.push(AbiParam {
            name: "_serialisedOutputs".into(),
            param_type: "ByteString".into(),
            fixed_array: None,
        });
    }

    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "IntentWitnessTest".to_string(),
        abi: Abi {
            constructor: AbiConstructor {
                params: vec![AbiParam {
                    name: "count".into(),
                    param_type: "bigint".into(),
                    fixed_array: None,
                }],
            },
            methods: vec![AbiMethod {
                name: "move".to_string(),
                params,
                is_public: true,
                is_terminal: None,
            }],
        },
        script: "51".to_string(),
        state_fields: Some(vec![StateField {
            name: "count".into(),
            field_type: "bigint".into(),
            index: 0,
            initial_value: None,
            fixed_array: None,
        }]),
        constructor_slots: None,
        code_sep_index_slots: None,
        // Stateful with codeSeparatorIndex=0 keeps the stateful branch active.
        code_separator_index: Some(0),
        code_separator_indices: None,
        anf: None,
    }
}

fn deploy_helper(
    artifact: RunarArtifact,
) -> (RunarContract, MockProvider, MockSigner) {
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let signer = MockSigner::new();
    let mut provider = MockProvider::testnet();
    let address = signer.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });
    contract.deploy(&mut provider, &signer, &DeployOptions {
        satoshis: 50_000,
        change_address: None,
    }).unwrap();
    // Funding UTXO for the call
    provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 1,
        satoshis: 100_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });
    (contract, provider, signer)
}

fn new_state_count(n: i64) -> CallOptions {
    let mut new_state = HashMap::new();
    new_state.insert("count".to_string(), SdkValue::Int(n));
    CallOptions {
        new_state: Some(new_state),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Filter: arg-count check excludes _prevOutScript_* / _serialisedOutputs
// ---------------------------------------------------------------------------

#[test]
fn filter_excludes_auto_injected_witness_params() {
    let artifact = make_intent_artifact(&[0, 1], true);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    contract.set_prev_out_script(0, "aa").unwrap();
    contract.set_prev_out_script(1, "bb").unwrap();
    contract.set_serialised_outputs("cc").unwrap();

    let opts = new_state_count(1);
    let result = contract.call("move", &[SdkValue::Int(123)], &mut provider, &signer, Some(&opts));
    assert!(result.is_ok(), "call failed: {:?}", result.err());
    assert_eq!(contract.state().get("count"), Some(&SdkValue::Int(1)));
}

#[test]
fn filter_still_rejects_real_arg_count_mismatch() {
    let artifact = make_intent_artifact(&[0], true);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    let result = contract.call(
        "move",
        &[SdkValue::Int(1), SdkValue::Int(2)],
        &mut provider, &signer, None,
    );
    let err = result.expect_err("expected arg count error");
    assert!(err.contains("expects 1 args, got 2"), "msg: {}", err);
}

// ---------------------------------------------------------------------------
// Missing witness ⇒ typed WitnessValueMissingError (carried in String error)
// ---------------------------------------------------------------------------

#[test]
fn missing_prev_out_script_raises_typed_error() {
    let artifact = make_intent_artifact(&[0], false);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    let err = contract
        .call("move", &[SdkValue::Int(1)], &mut provider, &signer, None)
        .expect_err("expected WitnessValueMissingError");
    assert!(err.contains("_prevOutScript_0"), "msg: {}", err);
    assert!(err.contains("IntentWitnessTest"), "msg: {}", err);
    assert!(err.contains("move"), "msg: {}", err);
}

#[test]
fn missing_serialised_outputs_raises_typed_error() {
    let artifact = make_intent_artifact(&[], true);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    let err = contract
        .call("move", &[SdkValue::Int(1)], &mut provider, &signer, None)
        .expect_err("expected WitnessValueMissingError");
    assert!(err.contains("_serialisedOutputs"), "msg: {}", err);
}

#[test]
fn witness_error_struct_is_constructible_and_displayable() {
    let err = WitnessValueMissingError {
        param_name: "_prevOutScript_3".into(),
        method_name: "spend".into(),
        contract_name: "Demo".into(),
    };
    let msg: String = err.clone().into();
    assert!(msg.contains("_prevOutScript_3"));
    assert!(msg.contains("Demo.spend"));
}

// ---------------------------------------------------------------------------
// Wiring: witness bytes appear in the broadcast unlocking script
// ---------------------------------------------------------------------------

#[test]
fn appends_multiple_prev_out_scripts_in_abi_order() {
    let artifact = make_intent_artifact(&[0, 1], false);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    contract.set_prev_out_script(0, "deadbeef").unwrap();
    contract.set_prev_out_script(1, "cafebabe").unwrap();

    let opts = new_state_count(1);
    contract.call("move", &[SdkValue::Int(1)], &mut provider, &signer, Some(&opts)).unwrap();

    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 2, "expected deploy + call");
    let call_tx_hex = &txs[1];
    let push0 = format!("04{}", "deadbeef");
    let push1 = format!("04{}", "cafebabe");
    let idx0 = call_tx_hex.find(&push0).expect("witness 0 push missing");
    let idx1 = call_tx_hex.find(&push1).expect("witness 1 push missing");
    assert!(idx1 > idx0, "witness 1 must follow witness 0 (idx0={}, idx1={})", idx0, idx1);
}

#[test]
fn appends_prev_out_then_serialised_in_abi_order() {
    let artifact = make_intent_artifact(&[0], true);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    contract.set_prev_out_script(0, "11223344").unwrap();
    contract.set_serialised_outputs("55667788").unwrap();

    let opts = new_state_count(1);
    contract.call("move", &[SdkValue::Int(1)], &mut provider, &signer, Some(&opts)).unwrap();

    let txs = provider.get_broadcasted_txs();
    let call_tx_hex = &txs[1];
    let idx_prev = call_tx_hex.find("0411223344").expect("prevOut push missing");
    let idx_serial = call_tx_hex.find("0455667788").expect("serialised push missing");
    assert!(idx_serial > idx_prev, "serialised must follow prevOut");
}

#[test]
fn accepts_bytes_via_convenience_setter() {
    let artifact = make_intent_artifact(&[0], false);
    let (mut contract, mut provider, signer) = deploy_helper(artifact);

    contract.set_prev_out_script_bytes(0, &[0xab, 0xcd]);
    let opts = new_state_count(1);
    contract.call("move", &[SdkValue::Int(1)], &mut provider, &signer, Some(&opts)).unwrap();
    let call_tx_hex = &provider.get_broadcasted_txs()[1];
    assert!(call_tx_hex.contains("02abcd"), "2-byte witness push missing");
}

#[test]
fn rejects_invalid_hex() {
    let artifact = make_intent_artifact(&[0], false);
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    assert!(contract.set_prev_out_script(0, "not-hex!").is_err());
    assert!(contract.set_serialised_outputs("abc").is_err());
}
