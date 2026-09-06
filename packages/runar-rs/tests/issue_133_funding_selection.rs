//! Issue #133 — call() must coin-select funding inputs, not sweep the wallet.
//!
//! The non-terminal call path previously forwarded every wallet UTXO (minus
//! the contract UTXO) as funding, producing an (N+1)-input tx no matter how
//! little funding the call needed. The fix uses smallest-sufficient
//! largest-first selection (`select_utxos`) plus a `CallOptions.max_funding_inputs`
//! cap that fails loudly when funding cannot be covered within the budget.

use std::collections::HashMap;

use runar_lang::sdk::{
    CallOptions, DeployOptions, MockProvider, MockSigner, RunarContract, SdkValue, Signer, Utxo,
};
use runar_lang::sdk::types::{
    Abi, AbiConstructor, AbiMethod, AbiParam, RunarArtifact, StateField,
};

/// A minimal stateful counter artifact: one mutable `count` field and a public
/// `increment` continuation method carrying the standard change-output params.
fn counter_artifact() -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "Counter".to_string(),
        parent_class: Some("StatefulSmartContract".to_string()),
        abi: Abi {
            constructor: AbiConstructor {
                params: vec![AbiParam { name: "count".into(), param_type: "bigint".into(), fixed_array: None }],
            },
            methods: vec![AbiMethod {
                name: "increment".to_string(),
                params: vec![
                    AbiParam { name: "_changePKH".into(), param_type: "Ripemd160".into(), fixed_array: None },
                    AbiParam { name: "_changeAmount".into(), param_type: "bigint".into(), fixed_array: None },
                    AbiParam { name: "_newAmount".into(), param_type: "bigint".into(), fixed_array: None },
                    AbiParam { name: "txPreimage".into(), param_type: "SigHashPreimage".into(), fixed_array: None },
                ],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: "51".to_string(),
        asm: None,
        state_fields: Some(vec![StateField {
            name: "count".into(),
            field_type: "bigint".into(),
            index: 0,
            initial_value: None,
            fixed_array: None,
        }]),
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: Some(0),
        code_separator_indices: None,
        anf: None,
    }
}

fn new_state_count(n: i64) -> HashMap<String, SdkValue> {
    let mut m = HashMap::new();
    m.insert("count".to_string(), SdkValue::Int(n));
    m
}

/// Deploy the counter with `deploy_sats`, then return a FRESH provider seeded
/// with exactly the `funding` spare UTXOs — so the call's candidate funding set
/// is precisely those coins (the deploy provider's leftovers do not leak in;
/// `call` spends `self.current_utxo` tracked from deploy, not a provider lookup).
fn deploy_with_wallet(
    deploy_sats: i64,
    funding: &[i64],
) -> (RunarContract, MockProvider, MockSigner) {
    let mut contract = RunarContract::new(counter_artifact(), vec![SdkValue::Int(0)]);
    let signer = MockSigner::new();
    let address = signer.get_address().unwrap();

    let mut deploy_provider = MockProvider::always_ack("testnet");
    deploy_provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: deploy_sats + 200_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });
    contract
        .deploy(&mut deploy_provider, &signer, &DeployOptions { satoshis: deploy_sats, change_address: None, funding_signer: None })
        .unwrap();

    let mut call_provider = MockProvider::always_ack("testnet");
    for (i, &sats) in funding.iter().enumerate() {
        call_provider.add_utxo(&address, Utxo {
            txid: format!("{:02x}", i + 0x40).repeat(32),
            output_index: 1,
            satoshis: sats,
            script: format!("76a914{}88ac", "00".repeat(20)),
        });
    }
    (contract, call_provider, signer)
}

/// Read the input count (varint, always 1 byte here) from a raw tx hex.
fn input_count(tx_hex: &str) -> usize {
    usize::from_str_radix(&tx_hex[8..10], 16).unwrap()
}

#[test]
fn call_selects_one_funding_input_not_all_spare_utxos() {
    // 3 spare 100k coins; an equal-value increment only needs fee coverage,
    // so exactly one funding input is selected -> 2 inputs, not 4.
    let (mut contract, mut provider, signer) = deploy_with_wallet(50_000, &[100_000, 100_000, 100_000]);
    let opts = CallOptions { new_state: Some(new_state_count(1)), ..Default::default() };
    contract
        .call("increment", &[], &mut provider, &signer, Some(&opts))
        .unwrap();
    let txs = provider.get_broadcasted_txs();
    let call_tx = &txs[0];
    assert_eq!(input_count(call_tx), 2, "expected 1 contract + 1 funding input");
}

#[test]
fn max_funding_inputs_errors_when_it_cannot_cover() {
    // Small coins force >1 funding input for a value-increasing continuation;
    // cap at 1 must return an error mentioning max_funding_inputs.
    let (mut contract, mut provider, signer) = deploy_with_wallet(1_000, &[3_000, 3_000, 3_000, 3_000]);
    let opts = CallOptions {
        satoshis: Some(5_000),
        new_state: Some(new_state_count(1)),
        max_funding_inputs: Some(1),
        ..Default::default()
    };
    let err = contract
        .call("increment", &[], &mut provider, &signer, Some(&opts))
        .unwrap_err();
    assert!(err.contains("max_funding_inputs"), "unexpected error: {}", err);
}

#[test]
fn max_funding_inputs_honored_when_sufficient() {
    let (mut contract, mut provider, signer) = deploy_with_wallet(1_000, &[3_000, 3_000, 3_000, 3_000]);
    let opts = CallOptions {
        satoshis: Some(5_000),
        new_state: Some(new_state_count(1)),
        max_funding_inputs: Some(3),
        ..Default::default()
    };
    contract
        .call("increment", &[], &mut provider, &signer, Some(&opts))
        .unwrap();
    let txs = provider.get_broadcasted_txs();
    let call_tx = &txs[0];
    // 1 contract + 2 funding coins to cover the ~4000-sat shortfall.
    assert_eq!(input_count(call_tx), 3);
}
