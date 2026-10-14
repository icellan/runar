//! N-271 — a call that supplies BOTH terminal_outputs and
//! additional_contract_inputs must refuse with a named error.
//!
//! `prepare_call_terminal` lays out exactly one contract input (plus an
//! optional fee/funding input) and never reads
//! `options.additional_contract_inputs` at all. Before the fix this test
//! proves the extra UTXO is silently dropped instead of being rejected or
//! spent -- the call succeeds and reports a txid, but the broadcast tx has
//! only one input, not two.
//!
//! This test does NOT prove additional_contract_inputs could ever be made to
//! work on the terminal path (merging it validly) -- only that dropping it
//! silently is unacceptable and must become a refusal.

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{CallOptions, DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};
use runar_lang::sdk::types::{Abi, AbiConstructor, AbiMethod, RunarArtifact, TerminalOutput};

const METHOD_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const CONTRACT_SATS: i64 = 50_000;

fn trivial_artifact() -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "Escrow".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor { params: vec![] },
            methods: vec![AbiMethod {
                name: "cancel".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: "51".to_string(), // OP_TRUE
        asm: None,
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_part_len_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
        unsound_primitives: None,
    }
}

#[test]
fn terminal_call_with_additional_contract_inputs_fails_closed() {
    let method_signer = LocalSigner::new(METHOD_KEY).unwrap();
    let mut provider = MockProvider::testnet();
    let address = method_signer.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "aa".repeat(32),
        output_index: 0,
        satoshis: 100_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(trivial_artifact(), Vec::<SdkValue>::new());
    contract
        .deploy(&mut provider, &method_signer, &DeployOptions {
            satoshis: CONTRACT_SATS,
            change_address: None,
            funding_signer: None,
            acknowledge_unsound: vec![],
        })
        .unwrap();

    let payout = "76a914bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb88ac".to_string();
    let extra_utxo = Utxo {
        txid: "ee".repeat(32),
        output_index: 0,
        satoshis: 1_000,
        script: "51".to_string(),
    };

    let opts = CallOptions {
        terminal_outputs: Some(vec![TerminalOutput {
            script_hex: payout,
            satoshis: CONTRACT_SATS,
        }]),
        additional_contract_inputs: Some(vec![extra_utxo]),
        ..Default::default()
    };

    let result = contract.call("cancel", &[], &mut provider, &method_signer, Some(&opts));
    let err = result.expect_err(
        "expected an error (additional_contract_inputs was silently dropped instead)",
    );
    assert!(
        err.contains("additional_contract_inputs"),
        "expected error to name additional_contract_inputs, got: {err}"
    );
}
