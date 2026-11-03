//! N-286: a stateful merge through the two-phase API (prepare_call /
//! finalize_call). Replays the shared cross-SDK vector
//! conformance/sdk-call/stateful-merge-prepared.json (produced by the TS SDK,
//! whose MockProvider Spend-validated all three inputs; re-checked with Spend
//! in conformance/sdk-call/stateful-merge.test.ts).
//!
//! Proves: given the vector's artifact, two contract UTXOs, funding UTXO and
//! key, Rust's prepare_call yields the same primary sighash and sig indices,
//! and finalize_call with the vector's primary signature broadcasts a tx
//! byte-equal to the TS reference (extra contract input's unlock, fee and
//! change included). Does not prove a live node.

use std::collections::HashMap;
use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};
use serde_json::Value;

fn utxo(v: &Value) -> Utxo {
    Utxo {
        txid: v["txid"].as_str().unwrap().to_string(),
        output_index: v["outputIndex"].as_u64().unwrap() as u32,
        satoshis: v["satoshis"].as_i64().unwrap(),
        script: v["script"].as_str().unwrap().to_string(),
    }
}

#[test]
fn n286_stateful_merge_prepare_finalize_matches_shared_vector() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/sdk-call/stateful-merge-prepared.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let artifact: RunarArtifact = serde_json::from_value(v["artifact"].clone()).unwrap();
    let e = &v["expected"];

    let signer = LocalSigner::new(v["privKeyHex"].as_str().unwrap()).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, utxo(&v["fundingUtxo"]));
    let cu = utxo(&v["contractUtxo"]);
    let eu = utxo(&v["extraContractUtxo"]);
    provider.add_contract_utxo(&cu.script.clone(), cu.clone());
    provider.add_contract_utxo(&format!("{}:extra", eu.script), eu.clone());

    let mut contract = RunarContract::from_utxo(artifact, &cu).unwrap();
    let opts = CallOptions {
        additional_contract_inputs: Some(vec![eu]),
        ..Default::default()
    };
    let prepared = contract
        .prepare_call(v["method"].as_str().unwrap(), &[SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("prepare_call with an extra contract input");
    assert_eq!(prepared.sig_indices, vec![e["sigIndices"][0].as_u64().unwrap() as usize]);
    assert_eq!(prepared.sighash, e["sighash"].as_str().unwrap());

    let mut sigs = HashMap::new();
    sigs.insert(0usize, e["primarySignatureHex"].as_str().unwrap().to_string());
    contract.finalize_call(&prepared, &sigs, &mut provider).expect("finalize_call");

    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0], e["referenceTxHex"].as_str().unwrap(), "broadcast tx differs from the shared TS vector");
}
