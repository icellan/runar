//! N-296: cross-tier rule for an explicit Sig in a merge's per-input args
//! (additional_contract_input_args): a Sig slot the primary call left
//! auto-signed (Auto) is ALWAYS signed by the connected signer for each
//! additional contract input; a caller-supplied value in that slot is
//! overwritten (TS reference).
//!
//! Proves: on the inputs of conformance/sdk-call/stateful-merge-prepared.json,
//! call() with (a) no per-input args and (b) an explicit garbage Sig in the
//! per-input args broadcasts a tx byte-equal to REFERENCE_TX_HEX (derived by
//! the TS SDK, Spend-validated on all three inputs by its MockProvider).
//! Does not prove: the other tiers (own tests, same constant), non-Sig slots,
//! or a live node.

use std::collections::HashMap;
use std::path::Path;

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};
use serde_json::Value;

const REFERENCE_TX_HEX: &str = "0100000003aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fdc0064dd80261ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f758777473044022016d9b7149d88580c58338a7b88ee659d8dd0907f9b4554b8578ae8cfc9035d2e02204c8ee039d8be1f37ad706758ed3c27461a1e5d5c0c6cb5e7b6ae07f3cac001dd4114751e76e8199196d454941c45d1b3a323f1433bd603efab010210274d7e0301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000fddf027676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a00000000000000001027000000000000ffffffff78f13c8368e06c1df3b12365a5931bac72b404b6556460db97e67497bcc74ae50000000041000000ffffffffcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fdc0064dd80261ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f75877747304402207fc70f00c182283bc456f171d1592fa23eaf76ca0e81ee818913738e93a7eed70220324ffa1f4bdd7c6020728b8110e1fa0833d501efe48a519fa8c7028571f98e624114751e76e8199196d454941c45d1b3a323f1433bd603efab010210274d7e0301000000f81f4842d6ef7032c06b4ab50d5a9c032c4704fa3f20d7267e850a75e8da307f82a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be8cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc01000000fddf027676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a00000000000000001027000000000000ffffffff78f13c8368e06c1df3b12365a5931bac72b404b6556460db97e67497bcc74ae50000000041000000ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000006b4830450221008c5a7f75980220af3f7fd9952e3696db1c030b90bd7e146667cb46c09d177ca202200d3d98d23b0268c6cd1a66b0f8418ff454ae65ce0b9a6a73a271952f4208eb4641210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff021027000000000000fde10261ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e818b21414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937782927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f82927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e21038ff83d8cf12121491609c4939dc11c4aa35503508fe432dc5a5c1905608b9218ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686857798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781557a210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ad768b7778820134947f77587f758153797ca269547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687c58805279547a7c7558806b5379016a7e7c7e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e6c7c7e7c7eaa7c820128947f7701207f7587776a0100000000000000efab0100000000001976a914751e76e8199196d454941c45d1b3a323f1433bd688ac00000000";

fn utxo(v: &Value) -> Utxo {
    Utxo {
        txid: v["txid"].as_str().unwrap().to_string(),
        output_index: v["outputIndex"].as_u64().unwrap() as u32,
        satoshis: v["satoshis"].as_i64().unwrap(),
        script: v["script"].as_str().unwrap().to_string(),
    }
}

fn merge(per_input_args: Option<Vec<Vec<SdkValue>>>) -> String {
    merge_at(per_input_args, None)
}

fn merge_at(per_input_args: Option<Vec<Vec<SdkValue>>>, fee_rate: Option<i64>) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/sdk-call/stateful-merge-prepared.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let artifact: RunarArtifact = serde_json::from_value(v["artifact"].clone()).unwrap();

    let signer = LocalSigner::new(v["privKeyHex"].as_str().unwrap()).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    if let Some(rate) = fee_rate {
        provider.set_fee_rate(rate);
    }
    provider.add_utxo(&address, utxo(&v["fundingUtxo"]));
    let cu = utxo(&v["contractUtxo"]);
    let eu = utxo(&v["extraContractUtxo"]);
    provider.add_contract_utxo(&cu.script.clone(), cu.clone());
    provider.add_contract_utxo(&format!("{}:extra", eu.script), eu.clone());

    let mut contract = RunarContract::from_utxo(artifact, &cu).unwrap();
    let mut new_state = HashMap::new();
    new_state.insert("count".to_string(), SdkValue::Int(1));
    let opts = CallOptions {
        additional_contract_inputs: Some(vec![eu]),
        additional_contract_input_args: per_input_args,
        new_state: Some(new_state),
        ..Default::default()
    };
    contract
        .call(v["method"].as_str().unwrap(), &[SdkValue::Auto], &mut provider, &signer, Some(&opts))
        .expect("merge call");
    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1);
    txs[0].clone()
}

#[test]
fn n296_merge_default_path_matches_reference() {
    assert_eq!(merge(None), REFERENCE_TX_HEX);
}

#[test]
fn n296_merge_explicit_sig_is_overwritten_by_signer() {
    let explicit = vec![vec![SdkValue::Bytes("ab".repeat(71))]];
    assert_eq!(merge(Some(explicit)), REFERENCE_TX_HEX);
}

fn varint(b: &[u8], i: usize) -> (u64, usize) {
    match b[i] {
        n @ 0..=0xfc => (n as u64, i + 1),
        m => {
            let w = match m { 0xfd => 2, 0xfe => 4, _ => 8 };
            let mut v = 0u64;
            for k in 0..w {
                v |= (b[i + 1 + k] as u64) << (8 * k);
            }
            (v, i + 1 + w)
        }
    }
}

/// Fee sizing for a merge: at 1000 sat/kB every byte the fee layout misses is a
/// satoshi under-paid. Each additional contract input's unlock carries
/// _changeAmount, so it must be sized with the real change, not 0 (the defect
/// the Java tier had; ported here as a cross-tier pin).
#[test]
fn n296_merge_fee_covers_every_byte_at_one_sat_per_byte() {
    let hex_tx = merge_at(None, Some(1000));
    let raw: Vec<u8> = (0..hex_tx.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex_tx[i..i + 2], 16).unwrap()).collect();
    let (n_in, mut i) = varint(&raw, 4);
    for _ in 0..n_in {
        let (sl, j) = varint(&raw, i + 36);
        i = j + sl as usize + 4;
    }
    let (n_out, mut i2) = varint(&raw, i);
    let mut out: i64 = 0;
    for _ in 0..n_out {
        let mut val = 0u64;
        for k in 0..8 {
            val |= (raw[i2 + k] as u64) << (8 * k);
        }
        out += val as i64;
        let (sl, j) = varint(&raw, i2 + 8);
        i2 = j + sl as usize;
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/sdk-call/stateful-merge-prepared.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let paid = utxo(&v["contractUtxo"]).satoshis + utxo(&v["extraContractUtxo"]).satoshis
        + utxo(&v["fundingUtxo"]).satoshis - out;
    assert!(paid >= raw.len() as i64, "paid {paid} sat for a {}-byte tx at 1 sat/byte", raw.len());
}
