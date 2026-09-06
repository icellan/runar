//! G6 — `SdkValue::Auto` for a ByteString param is only meaningful for the
//! auto-computed `allPrevouts` slot.
//!
//! For any other ByteString parameter it is a caller mistake, and silently
//! substituting the `36 * n` zero-byte prevouts stub hands the contract outpoint
//! bytes where it expected its own value: the transaction broadcasts and then
//! fails at script execution with an opaque error. Fail at build time instead,
//! naming the parameter.
//!
//! `Auto` for a `Sig` param (auto-sign) must keep working untouched.

use runar_lang::sdk::{
    CallOptions, DeployOptions, MockProvider, MockSigner, RunarContract, SdkValue, Signer, Utxo,
};
use runar_lang::sdk::types::{Abi, AbiConstructor, AbiMethod, AbiParam, RunarArtifact, StateField};

fn make_artifact(byte_string_param_name: &str) -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "NullByteStringArgTest".to_string(),
        parent_class: None,
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
                params: vec![
                    AbiParam { name: "sig".into(), param_type: "Sig".into(), fixed_array: None },
                    AbiParam {
                        name: byte_string_param_name.into(),
                        param_type: "ByteString".into(),
                        fixed_array: None,
                    },
                    AbiParam { name: "_changePKH".into(), param_type: "Ripemd160".into(), fixed_array: None },
                    AbiParam { name: "_changeAmount".into(), param_type: "bigint".into(), fixed_array: None },
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

fn deploy_helper(artifact: RunarArtifact) -> (RunarContract, MockProvider, MockSigner) {
    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(0)]);
    let signer = MockSigner::new();
    let mut provider = MockProvider::always_ack("testnet");
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
        funding_signer: None,
    }).unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "bb".repeat(32),
        output_index: 1,
        satoshis: 100_000,
        script: format!("76a914{}88ac", "00".repeat(20)),
    });
    (contract, provider, signer)
}

#[test]
fn auto_bytestring_arg_rejected_for_non_prevouts_param() {
    let (mut contract, mut provider, signer) = deploy_helper(make_artifact("memo"));
    let err = contract
        .prepare_call("move", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, None)
        .expect_err("Auto for the ByteString param 'memo' must be rejected");
    assert!(err.contains("memo"), "error must name the offending parameter, got: {err}");
}

#[test]
fn auto_bytestring_arg_all_prevouts_still_auto_resolves() {
    let (mut contract, mut provider, signer) = deploy_helper(make_artifact("allPrevouts"));
    let result =
        contract.prepare_call("move", &[SdkValue::Auto, SdkValue::Auto], &mut provider, &signer, None);
    assert!(result.is_ok(), "Auto allPrevouts must still auto-resolve: {:?}", result.err());
}

#[test]
fn auto_sig_arg_still_auto_signs() {
    let (mut contract, mut provider, signer) = deploy_helper(make_artifact("memo"));
    let result = contract.prepare_call(
        "move",
        &[SdkValue::Auto, SdkValue::Bytes("deadbeef".into())],
        &mut provider,
        &signer,
        None,
    );
    assert!(result.is_ok(), "Auto Sig arg must still auto-sign: {:?}", result.err());
}

#[test]
fn auto_bytestring_arg_rejected_for_additional_contract_input_args() {
    let (mut contract, mut provider, signer) = deploy_helper(make_artifact("memo"));
    let extra = Utxo {
        txid: "cc".repeat(32),
        output_index: 0,
        satoshis: 5_000,
        script: contract.get_utxo().unwrap().script.clone(),
    };
    let opts = CallOptions {
        additional_contract_inputs: Some(vec![extra]),
        additional_contract_input_args: Some(vec![vec![SdkValue::Auto, SdkValue::Auto]]),
        ..Default::default()
    };
    let err = contract
        .prepare_call(
            "move",
            &[SdkValue::Auto, SdkValue::Bytes("deadbeef".into())],
            &mut provider,
            &signer,
            Some(&opts),
        )
        .expect_err("Auto ByteString in additional_contract_input_args must be rejected");
    assert!(err.contains("memo"), "error must name the offending parameter, got: {err}");
}
