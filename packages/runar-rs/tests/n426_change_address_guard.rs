//! N-426: the stateful change-address guard. Replays the shared cross-SDK
//! vector conformance/sdk-call/n426-change-address-guard.json (TS reference,
//! Spend-validated in conformance/sdk-call/n426-change-address-guard.test.ts).
//!
//! Proves: on a stateful method that takes _changePKH, prepare_call refuses a
//! change_address for another key (no change_pub_key) with the shared message
//! and broadcasts nothing; change_address + the matching change_pub_key and a
//! change_address equal to the signer's own address are accepted.
//! Does not prove: the terminal path, finalize_call, or a live node.

use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, LocalSigner, MockProvider, PreparedCall, RunarContract, SdkValue, Signer, Utxo};
use serde_json::Value;

fn utxo(v: &Value) -> Utxo {
    Utxo {
        txid: v["txid"].as_str().unwrap().to_string(),
        output_index: v["outputIndex"].as_u64().unwrap() as u32,
        satoshis: v["satoshis"].as_i64().unwrap(),
        script: v["script"].as_str().unwrap().to_string(),
    }
}

fn load(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/sdk-call").join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn prepare(opts: &CallOptions) -> (Result<PreparedCall, String>, MockProvider) {
    let g = load("n426-change-address-guard.json");
    let v = load("stateful-merge-prepared.json");
    let artifact: RunarArtifact = serde_json::from_value(v["artifact"].clone()).unwrap();
    let signer = LocalSigner::new(v["privKeyHex"].as_str().unwrap()).unwrap();
    let address = signer.get_address().unwrap();
    assert_eq!(address, g["ownAddress"].as_str().unwrap());
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, utxo(&v["fundingUtxo"]));
    let cu = utxo(&v["contractUtxo"]);
    provider.add_contract_utxo(&cu.script.clone(), cu.clone());
    let mut contract = RunarContract::from_utxo(artifact, &cu).unwrap();
    let r = contract.prepare_call(v["method"].as_str().unwrap(), &[SdkValue::Auto], &mut provider, &signer, Some(opts));
    (r, provider)
}

#[test]
fn n426_refuses_change_address_for_another_key_without_change_pub_key() {
    let g = load("n426-change-address-guard.json");
    let other = g["otherAddress"].as_str().unwrap();
    let (r, provider) = prepare(&CallOptions { change_address: Some(other.to_string()), ..Default::default() });
    let want = g["message"].as_str().unwrap().replace("{changeAddress}", other);
    let err = r.err().expect("must refuse");
    assert!(err.contains(&want), "err = {err:?}, want it to contain {want:?}");
    assert_eq!(provider.get_broadcasted_txs().len(), 0);
}

#[test]
fn n426_accepts_change_address_with_matching_change_pub_key() {
    let g = load("n426-change-address-guard.json");
    let (r, _) = prepare(&CallOptions {
        change_address: Some(g["otherAddress"].as_str().unwrap().to_string()),
        change_pub_key: Some(g["otherPubKeyHex"].as_str().unwrap().to_string()),
        ..Default::default()
    });
    r.expect("prepare_call");
}

#[test]
fn n426_accepts_change_address_equal_to_signers_own_address() {
    let g = load("n426-change-address-guard.json");
    let (r, _) = prepare(&CallOptions {
        change_address: Some(g["ownAddress"].as_str().unwrap().to_string()),
        ..Default::default()
    });
    r.expect("prepare_call");
}
