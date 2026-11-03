//! N-412: a STATELESS contract method that takes the auto-injected intent
//! witness `_prevOutScript_0`. Replays the shared cross-SDK vector
//! conformance/sdk-call/stateless-witness.json (produced by the TS SDK, whose
//! MockProvider Spend-validated every input; re-checked with @bsv/sdk Spend —
//! including a tampered/omitted witness push — in
//! conformance/sdk-call/stateless-witness.test.ts).
//!
//! Proves: Rust's call (no-Sig `peek`, Sig `spend`) and prepare_call +
//! finalize_call (`spend`) push `<declared args> <witness> <selector>` on input
//! 0 and broadcast a tx byte-equal to the TS reference. Does not prove a live
//! node, or `_serialisedOutputs` on a stateless method (the compiler refuses
//! requireOutputP2PKH outside StatefulSmartContract).

use std::collections::HashMap;
use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};
use serde_json::Value;

fn utxo(v: &Value) -> Utxo {
    Utxo {
        txid: v["txid"].as_str().unwrap().to_string(),
        output_index: v["outputIndex"].as_u64().unwrap() as u32,
        satoshis: v["satoshis"].as_i64().unwrap(),
        script: v["script"].as_str().unwrap().to_string(),
    }
}

fn load() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/sdk-call/stateless-witness.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn fresh(v: &Value) -> (RunarContract, MockProvider, LocalSigner) {
    let artifact: RunarArtifact = serde_json::from_value(v["artifact"].clone()).unwrap();
    let signer = LocalSigner::new(v["privKeyHex"].as_str().unwrap()).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, utxo(&v["fundingUtxo"]));
    let cu = utxo(&v["contractUtxo"]);
    provider.add_contract_utxo(&cu.script.clone(), cu.clone());
    let mut contract = RunarContract::from_utxo(artifact, &cu).unwrap();
    contract
        .set_prev_out_script(0, v["prevOutScriptHex"].as_str().unwrap())
        .unwrap();
    (contract, provider, signer)
}

fn assert_broadcast(provider: &MockProvider, want: &Value) {
    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1);
    let unlock = want["input0UnlockingHex"].as_str().unwrap();
    assert!(
        txs[0].contains(unlock),
        "input 0 unlocking script {unlock} not in broadcast tx {}",
        txs[0]
    );
    assert_eq!(txs[0], want["referenceTxHex"].as_str().unwrap(), "broadcast tx differs from the shared TS vector");
}

#[test]
fn n412_stateless_intent_witness_call_peek() {
    let v = load();
    let (mut contract, mut provider, signer) = fresh(&v);
    contract
        .call("peek", &[SdkValue::Int(5)], &mut provider, &signer, None)
        .expect("call peek");
    assert_broadcast(&provider, &v["expected"]["peek"]);
}

#[test]
fn n412_stateless_intent_witness_call_spend() {
    let v = load();
    let (mut contract, mut provider, signer) = fresh(&v);
    let pk = SdkValue::Bytes(v["pubKeyHex"].as_str().unwrap().to_string());
    contract
        .call("spend", &[SdkValue::Auto, pk], &mut provider, &signer, None)
        .expect("call spend");
    assert_broadcast(&provider, &v["expected"]["spend"]);
}

#[test]
fn n412_stateless_intent_witness_prepare_finalize_spend() {
    let v = load();
    let (mut contract, mut provider, signer) = fresh(&v);
    let pk = SdkValue::Bytes(v["pubKeyHex"].as_str().unwrap().to_string());
    let prepared = contract
        .prepare_call("spend", &[SdkValue::Auto, pk], &mut provider, &signer, None)
        .expect("prepare_call spend");
    assert_eq!(prepared.sig_indices, vec![0usize]);
    let mut sigs = HashMap::new();
    sigs.insert(0usize, v["expected"]["spend"]["signatureHex"].as_str().unwrap().to_string());
    contract.finalize_call(&prepared, &sigs, &mut provider).expect("finalize_call");
    assert_broadcast(&provider, &v["expected"]["spend"]);
}
