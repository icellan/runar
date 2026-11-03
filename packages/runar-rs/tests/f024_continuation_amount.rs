//! F-024 (R14): the SDK's ANF interpreter derives the post-call state before
//! the tx exists; the covenant re-derives it on-chain. For a contract whose
//! state depends on `continuationAmount()` (the injected `_newAmount`) and
//! `extractAmount(txPreimage)` (the spent UTXO's satoshis), the SDK must feed
//! the interpreter those real values.
//!
//! Proves: the Rust SDK call path derives `lastDeposit = continuation - input`
//! from the call's real amounts, and the interpreter reads a caller-bound
//! `_newAmount` / integer `txPreimage`. Does NOT prove on-chain acceptance: the
//! Rust ScriptVm cannot validate an OP_PUSH_TX covenant (see
//! continuation_satoshis_addoutput.rs); the TS/Go SDK tests cover the spend.

use std::collections::HashMap;

use runar_lang::sdk::anf_interpreter::compute_new_state;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

const SRC: &str = r#"
class Tip extends StatefulSmartContract {
  lastDeposit: bigint;
  constructor(lastDeposit: bigint) { super(lastDeposit); this.lastDeposit = lastDeposit; }
  public deposit() {
    this.lastDeposit = continuationAmount() - extractAmount(this.txPreimage);
  }
}
"#;

fn artifact() -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(SRC, Some("Tip.runar.ts")).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

#[test]
fn interpreter_reads_caller_bound_new_amount_and_input_amount() {
    let art = artifact();
    let mut state = HashMap::new();
    state.insert("lastDeposit".to_string(), SdkValue::Int(0));
    let mut args = HashMap::new();
    args.insert("_newAmount".to_string(), SdkValue::Int(7_000));
    args.insert("txPreimage".to_string(), SdkValue::Int(5_000));
    let out = compute_new_state(art.anf.as_ref().unwrap(), "deposit", &state, &args, &[]).unwrap();
    assert!(matches!(out.get("lastDeposit"), Some(SdkValue::Int(2_000))), "{:?}", out);
}

#[test]
fn call_path_derives_state_from_the_real_amounts() {
    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 500_000, script: build_p2pkh_script(&address) });
    let mut contract = RunarContract::new(artifact(), vec![SdkValue::Int(0)]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions { satoshis: 10_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] })
        .expect("deploy");
    let opts = CallOptions { satoshis: Some(12_500), ..Default::default() };
    contract.call("deposit", &[], &mut provider, &signer, Some(&opts)).expect("call");
    assert!(matches!(contract.state().get("lastDeposit"), Some(SdkValue::Int(2_500))), "{:?}", contract.state());
}
