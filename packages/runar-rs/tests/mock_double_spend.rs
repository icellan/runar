//! `MockProvider` must refuse a double spend: a second, DIFFERENT transaction
//! spending an outpoint an earlier accepted broadcast already spent. A node
//! refuses it, so acking it lets a test "succeed" at a spend the network
//! rejects.

use bsv::script::{LockingScript, UnlockingScript};
use bsv::transaction::{
    Transaction as BsvTx, TransactionInput as BsvTxIn, TransactionOutput as BsvTxOut,
};
use runar_lang::sdk::{MockProvider, Provider, Utxo};

fn input(prev_txid: &str) -> BsvTxIn {
    BsvTxIn {
        source_txid: Some(prev_txid.to_string()),
        source_output_index: 0,
        unlocking_script: Some(UnlockingScript::from_hex("").unwrap()),
        sequence: 0xffff_ffff,
        source_transaction: None,
    }
}

fn spend(prev_txid: &str, out_sats: u64) -> BsvTx {
    let mut tx = BsvTx::new();
    tx.add_input(input(prev_txid));
    tx.add_output(BsvTxOut {
        satoshis: Some(out_sats),
        locking_script: LockingScript::from_hex("51").unwrap(),
        change: false,
    });
    tx
}

/// Deploy: broadcast a tx creating an OP_TRUE output; return its txid.
fn deploy(p: &mut MockProvider) -> String {
    let fund = "ab".repeat(32);
    p.add_utxo("funder", Utxo { txid: fund.clone(), output_index: 0, satoshis: 10_000, script: "51".into() });
    p.broadcast(&spend(&fund, 9_000)).expect("deploy broadcast")
}

#[test]
fn refuses_a_double_spend() {
    let mut p = MockProvider::testnet();
    let d = deploy(&mut p);
    let first = spend(&d, 8_000);
    p.broadcast(&first).expect("first spend");
    let conflicting = spend(&d, 7_000);
    assert_ne!(first.id().unwrap(), conflicting.id().unwrap());
    let before = p.get_broadcasted_txs().len();
    let err = p.broadcast(&conflicting).expect_err("MockProvider accepted a double spend");
    assert!(err.contains("already spent"), "{}", err);
    assert_eq!(p.get_broadcasted_txs().len(), before, "a refused broadcast was recorded");
}

#[test]
fn refuses_a_tx_spending_one_outpoint_twice() {
    let mut p = MockProvider::testnet();
    let d = deploy(&mut p);
    let mut tx = spend(&d, 8_000);
    tx.add_input(input(&d));
    let err = p.broadcast(&tx).expect_err("a tx spending one outpoint twice must be refused");
    assert!(err.contains("more than once"), "{}", err);
}

#[test]
fn get_utxos_omits_an_outpoint_an_accepted_broadcast_spent() {
    let mut p = MockProvider::testnet();
    p.add_utxo("funder", Utxo { txid: "ab".repeat(32), output_index: 1, satoshis: 5_000, script: "51".into() });
    deploy(&mut p);
    let left: Vec<u32> = p.get_utxos("funder").unwrap().iter().map(|u| u.output_index).collect();
    assert_eq!(left, vec![1]);
}

#[test]
fn get_utxos_lists_a_new_p2pkh_output_under_the_address_it_pays() {
    let mut p = MockProvider::testnet();
    let pkh = "1111111111111111111111111111111111111111";
    p.add_utxo(pkh, Utxo { txid: "cd".repeat(32), output_index: 0, satoshis: 1, script: "51".into() });
    let fund = "ab".repeat(32);
    p.add_utxo("funder", Utxo { txid: fund.clone(), output_index: 0, satoshis: 10_000, script: "51".into() });
    let mut tx = spend(&fund, 9_000);
    tx.outputs[0].locking_script = LockingScript::from_hex("76a914111111111111111111111111111111111111111188ac").unwrap();
    let txid = p.broadcast(&tx).expect("broadcast");
    let listed: Vec<Utxo> = p.get_utxos(pkh).unwrap().into_iter().filter(|u| u.txid == txid).collect();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].output_index, listed[0].satoshis, listed[0].script.as_str()), (0, 9_000, "76a914111111111111111111111111111111111111111188ac"));
}

#[test]
fn a_refused_broadcast_does_not_spend_its_inputs() {
    let mut p = MockProvider::testnet();
    let d = deploy(&mut p);
    assert!(p.broadcast(&spend(&d, 50_000)).is_err(), "underfunded spend must be refused");
    p.broadcast(&spend(&d, 8_000)).expect("outpoint must still be spendable");
}

#[test]
fn identical_rebroadcast_is_not_a_double_spend() {
    let mut p = MockProvider::testnet();
    let d = deploy(&mut p);
    let tx = spend(&d, 8_000);
    let first = p.broadcast(&tx).expect("first broadcast");
    let before = p.get_broadcasted_txs().len();
    let again = p.broadcast(&tx).expect("re-broadcasting the identical tx must not be a double spend");
    assert_eq!(again, first, "re-broadcast must return the first txid");
    assert_eq!(p.get_broadcasted_txs().len(), before, "re-broadcast must register nothing new");
}
