//! N-253: since F-369/N-213 the k=1 OP_PUSH_TX ECDSA signature is unused on the
//! stateful prepare_call path (the on-chain script derives it from the
//! preimage), yet the path still computed and discarded one per pass. The fix
//! adds `compute_op_push_tx_preimage_with_code_sep_sighash` and uses it there.
//!
//! Proves: a stateful merge prepare_call (the shared N-286 vector: primary +
//! extra contract input) performs zero OP_PUSH_TX signs, counted through
//! `OP_PUSH_TX_SIGN_COUNT`; the control shows the counter does see the signing
//! helper, and that the preimage-only variant returns the identical preimage
//! without signing. Byte-identity of the prepare_call output is proven by
//! n286_stateful_merge_prepared. Says nothing about the stateless / terminal
//! paths. One test fn: the counter is process-global.

use std::path::Path;
use std::sync::atomic::Ordering;

use runar_lang::sdk::oppushtx::{
    compute_op_push_tx_preimage_with_code_sep_sighash, compute_op_push_tx_with_code_sep_sighash,
    OP_PUSH_TX_SIGN_COUNT,
};
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
fn n253_stateful_prepare_call_computes_no_op_push_tx_signature() {
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
    let before = OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed);
    let prepared = contract
        .prepare_call(v["method"].as_str().unwrap(), &[SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("prepare_call with an extra contract input");
    assert_eq!(prepared.sighash, e["sighash"].as_str().unwrap());
    let signs = OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed) - before;
    assert_eq!(signs, 0, "stateful prepare_call computed {} OP_PUSH_TX signature(s); want 0", signs);

    // Control: the signing helper bumps the counter; the preimage-only variant
    // returns the same preimage and does not.
    let tx_hex = e["referenceTxHex"].as_str().unwrap();
    let cus = utxo(&v["contractUtxo"]);
    for flag in [0x41u32, 0x43] {
        let before = OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed);
        let (_sig, full) =
            compute_op_push_tx_with_code_sep_sighash(tx_hex, 0, &cus.script, cus.satoshis, -1, flag).unwrap();
        assert_eq!(OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed), before + 1);
        let only =
            compute_op_push_tx_preimage_with_code_sep_sighash(tx_hex, 0, &cus.script, cus.satoshis, -1, flag).unwrap();
        assert_eq!(OP_PUSH_TX_SIGN_COUNT.load(Ordering::Relaxed), before + 1);
        assert_eq!(only, full);
    }
    assert!(compute_op_push_tx_preimage_with_code_sep_sighash(tx_hex, 0, "", 1, -1, 0x41).is_err());
    assert!(compute_op_push_tx_preimage_with_code_sep_sighash(tx_hex, 99, &cus.script, 1, -1, 0x41).is_err());
}
