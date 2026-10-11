//! N-038 (R64): a stateful `@sighash SINGLE|FORKID` call carrying a change
//! output, replayed against the shared cross-SDK vector
//! `conformance/sdk-call/sighash-single-stateful.json` (produced by the TS SDK
//! and Spend-validated in `conformance/sdk-call/sdk-call.test.ts`).
//!
//! Proves: the Rust SDK pushes byte-identical input-0 unlocking bytes (with the
//! `_codePart` prefix and NO `_changePKH` / `_changeAmount` — the SINGLE
//! method's ABI declares none), builds the same continuation output[0], still
//! adds a change output, and tracks the new state. Under SINGLE the preimage
//! commits only the inputs and output[0], so byte equality with the
//! Spend-validated TS bytes is the covenant condition.
//! Does NOT prove on-chain acceptance by a Rust interpreter: the Rust ScriptVm
//! (bsv-sdk Spend) cannot run Rúnar OP_PUSH_TX covenants (pre-Chronicle
//! OP_2MUL, see tests/g1_raw_outputs_spend.rs), so the tamper-reject half lives
//! in the TS and Go replays of the same vector.

use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{LocalSigner, MockProvider, RunarContract, SdkValue, Utxo};
use serde_json::Value;

fn utxo(v: &Value) -> Utxo {
    Utxo {
        txid: v["txid"].as_str().unwrap().to_string(),
        output_index: v["outputIndex"].as_u64().unwrap() as u32,
        satoshis: v["satoshis"].as_i64().unwrap(),
        script: v["script"].as_str().unwrap().to_string(),
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn read_varint(b: &[u8], p: &mut usize) -> usize {
    let first = b[*p];
    *p += 1;
    match first {
        0xfd => {
            let v = b[*p] as usize | (b[*p + 1] as usize) << 8;
            *p += 2;
            v
        }
        0xfe => {
            let v = (0..4).map(|i| (b[*p + i] as usize) << (8 * i)).sum();
            *p += 4;
            v
        }
        0xff => panic!("8-byte varint not expected"),
        n => n as usize,
    }
}

/// (input unlocking scripts, outputs as (satoshis, script)) of a raw tx.
fn parse_tx(tx_hex: &str) -> (Vec<String>, Vec<(i64, String)>) {
    let b = unhex(tx_hex);
    let mut p = 4usize;
    let mut ins = Vec::new();
    for _ in 0..read_varint(&b, &mut p) {
        p += 36;
        let n = read_varint(&b, &mut p);
        ins.push(tohex(&b[p..p + n]));
        p += n + 4;
    }
    let mut outs = Vec::new();
    for _ in 0..read_varint(&b, &mut p) {
        let sats = (0..8).map(|i| (b[p + i] as i64) << (8 * i)).sum();
        p += 8;
        let n = read_varint(&b, &mut p);
        outs.push((sats, tohex(&b[p..p + n])));
        p += n;
    }
    (ins, outs)
}

#[test]
fn n038_sighash_single_call_with_change_matches_shared_vector() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/sdk-call/sighash-single-stateful.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let artifact: RunarArtifact = serde_json::from_value(v["artifact"].clone()).unwrap();

    let signer = LocalSigner::new(v["privKeyHex"].as_str().unwrap()).unwrap();
    use runar_lang::sdk::Signer;
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, utxo(&v["fundingUtxo"]));
    let cu = utxo(&v["contractUtxo"]);
    provider.add_contract_utxo(&cu.script.clone(), cu.clone());

    let mut contract = RunarContract::from_utxo(artifact, &cu).unwrap();
    contract
        .call(v["method"].as_str().unwrap(), &[], &mut provider, &signer, None)
        .expect("SINGLE call with change should build and broadcast");

    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1);
    let (ins, outs) = parse_tx(&txs[0]);
    let e = &v["expected"];
    assert_eq!(outs.len() as u64, e["outputCount"].as_u64().unwrap(), "continuation + change");
    assert_eq!(outs[0].0, e["output0"]["satoshis"].as_i64().unwrap());
    assert_eq!(outs[0].1, e["output0"]["scriptHex"].as_str().unwrap());
    assert_eq!(contract.state().get("count"), Some(&SdkValue::Int(1)));
    assert_eq!(
        ins[0],
        e["input0UnlockingHex"].as_str().unwrap(),
        "input 0 unlocking script differs from the shared vector"
    );
}
