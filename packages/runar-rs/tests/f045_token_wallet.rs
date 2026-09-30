//! F-045: `TokenWallet::transfer` / `::merge` must sign the transaction that is
//! actually broadcast. Pre-fix both BIP-143-signed a locally built throwaway tx
//! and passed that concrete Sig into `call`, which skips auto-signing and
//! builds a different tx; `merge` also left the second token UTXO unspent.
//!
//! # Oracle (no Spend replay)
//!
//! The Rust `bsv-sdk` `Spend` cannot run a Rúnar OP_PUSH_TX covenant (it
//! hard-disables `OP_2MUL`; see `continuation_satoshis_addoutput.rs`), so the
//! stateful token inputs here are not script-executed. Instead: every signature
//! the wallet's signer produced for a TOKEN input must have been computed over
//! a tx whose BIP-143-relevant bytes (version, every outpoint + sequence, every
//! output, locktime — i.e. the tx with unlocking scripts blanked) equal the
//! broadcast tx's. BIP-143 covers nothing else apart from the subscript and
//! amount, which the SDK takes from the spent UTXO. Pre-fix the transfer
//! signature covers a tx with different outputs/inputs, so this goes RED. The
//! on-chain verdict for the same flow is proven by the TS/Go F-045 tests.
//!
//! Proves: each token-input signature covers the broadcast tx, and merge spends
//! BOTH token outpoints exactly once. Does NOT prove: script execution in this
//! tier, node acceptance, or token semantics beyond this fixture.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use runar_lang::sdk::contract::hex_to_bsv_tx;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::token_wallet::TokenWallet;
use runar_lang::sdk::types::{RunarArtifact, TransactionData, TxOutput};
use runar_lang::sdk::{LocalSigner, MockProvider, Provider, RunarContract, SdkValue, Signer, Utxo};

const HOLDER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000045";
const OTHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000047";

const SRC: &str = r#"
import { StatefulSmartContract, assert, checkSig, len } from 'runar-lang';
import type { PubKey, Sig, Addr } from 'runar-lang';

class WalletToken extends StatefulSmartContract {
  supply: bigint;
  holder: PubKey;

  constructor(supply: bigint, holder: PubKey) {
    super(supply, holder);
    this.supply = supply;
    this.holder = holder;
  }

  public transfer(sig: Sig, to: Addr) {
    assert(checkSig(sig, this.holder));
    assert(len(to) === 20n);
  }

  public merge(sig: Sig, otherSupply: bigint, otherHolder: PubKey) {
    assert(checkSig(sig, this.holder));
    assert(otherHolder === this.holder);
    assert(otherSupply >= 0n);
    this.supply = this.supply + otherSupply;
  }
}
"#;

fn artifact() -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(SRC, Some("WalletToken.runar.ts")).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

/// Shares one MockProvider between the wallet (which owns a Box) and the test.
struct Shared(Rc<RefCell<MockProvider>>, String);
impl Provider for Shared {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> { self.0.borrow().get_transaction(txid) }
    fn broadcast(&mut self, tx: &bsv::transaction::Transaction) -> Result<String, String> { self.0.borrow_mut().broadcast(tx) }
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> { self.0.borrow().get_utxos(address) }
    fn get_contract_utxo(&self, h: &str) -> Result<Option<Utxo>, String> { self.0.borrow().get_contract_utxo(h) }
    fn get_network(&self) -> &str { &self.1 }
    fn get_fee_rate(&self) -> Result<i64, String> { self.0.borrow().get_fee_rate() }
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> { self.0.borrow().get_raw_transaction(txid) }
}

type Log = Rc<RefCell<Vec<(String, usize)>>>;

/// LocalSigner that records every (tx_hex, input_index) it signs.
struct Recording(LocalSigner, Log);
impl Signer for Recording {
    fn get_public_key(&self) -> Result<String, String> { self.0.get_public_key() }
    fn get_address(&self) -> Result<String, String> { self.0.get_address() }
    fn sign(&self, tx_hex: &str, i: usize, sub: &str, sats: i64, t: Option<u32>) -> Result<String, String> {
        self.1.borrow_mut().push((tx_hex.to_string(), i));
        self.0.sign(tx_hex, i, sub, sats, t)
    }
}

/// The tx with every unlocking script blanked: exactly the bytes BIP-143 reads.
fn sighash_view(tx_hex: &str) -> String {
    let mut tx = hex_to_bsv_tx(tx_hex).unwrap();
    for inp in tx.inputs.iter_mut() {
        inp.unlocking_script = Some(bsv::script::UnlockingScript::from_hex("").unwrap());
    }
    tx.to_hex().unwrap()
}

fn outpoints(tx_hex: &str) -> Vec<String> {
    let tx = hex_to_bsv_tx(tx_hex).unwrap();
    tx.inputs.iter().map(|i| format!("{}:{}", i.source_txid.clone().unwrap(), i.source_output_index)).collect()
}

struct Fixture {
    provider: Rc<RefCell<MockProvider>>,
    wallet: TokenWallet,
    tokens: Vec<Utxo>,
    log: Log,
}

fn setup(art: &RunarArtifact, supplies: &[i64], token_sats: i64, funding_sats: i64) -> Fixture {
    let holder = LocalSigner::new(HOLDER_KEY).unwrap();
    let addr = holder.get_address().unwrap();
    let pubkey = holder.get_public_key().unwrap();
    let provider = Rc::new(RefCell::new(MockProvider::testnet()));
    let mut tokens = vec![];
    for (i, s) in supplies.iter().enumerate() {
        let c = RunarContract::new(art.clone(), vec![SdkValue::Int(*s), SdkValue::Bytes(pubkey.clone())]);
        let lock = c.get_locking_script();
        let txid = format!("{:02x}", i + 1).repeat(32);
        provider.borrow_mut().add_transaction(TransactionData {
            txid: txid.clone(), version: 1, inputs: vec![],
            outputs: vec![TxOutput { satoshis: token_sats, script: lock.clone() }], locktime: 0, raw: None,
        });
        let u = Utxo { txid, output_index: 0, satoshis: token_sats, script: lock };
        provider.borrow_mut().add_utxo(&addr, u.clone());
        tokens.push(u);
    }
    provider.borrow_mut().add_utxo(&addr, Utxo {
        txid: "fe".repeat(32), output_index: 0, satoshis: funding_sats, script: build_p2pkh_script(&addr),
    });
    let log: Log = Rc::new(RefCell::new(vec![]));
    let wallet = TokenWallet::new(
        art.clone(),
        Box::new(Shared(provider.clone(), "testnet".into())),
        Box::new(Recording(holder, log.clone())),
    );
    Fixture { provider, wallet, tokens, log }
}

/// Every signature made for a token input covers the broadcast tx.
fn assert_token_sigs_cover(f: &Fixture, broadcast: &str) {
    let want = sighash_view(broadcast);
    let spent = outpoints(broadcast);
    let token_idx: Vec<usize> = f.tokens.iter()
        .filter_map(|u| spent.iter().position(|s| *s == format!("{}:0", u.txid)))
        .collect();
    assert!(!token_idx.is_empty(), "no token input in the broadcast tx: {:?}", spent);
    let log = f.log.borrow();
    for idx in token_idx {
        // The LAST signature the signer produced for this input is the one
        // embedded (the SDK re-signs after its second pass).
        let (tx_hex, _) = log.iter().rev().find(|(_, i)| *i == idx)
            .unwrap_or_else(|| panic!("signer never signed token input {}", idx));
        assert_eq!(sighash_view(tx_hex), want, "token input {} was signed over a different tx", idx);
    }
}

#[test]
fn transfer_signs_the_broadcast_tx() {
    let art = artifact();
    let other = LocalSigner::new(OTHER_KEY).unwrap();
    let other_addr = other.get_address().unwrap();
    // Raw hash160 isolates signing; the Base58 address is the documented form.
    for recipient in [build_p2pkh_script(&other_addr)[6..46].to_string(), other_addr.clone()] {
        let mut f = setup(&art, &[100], 5_000, 200_000);
        f.wallet.transfer(&recipient, 100).expect("transfer");
        let broadcast = f.provider.borrow().get_broadcasted_txs().last().unwrap().clone();
        assert_eq!(outpoints(&broadcast)[0], format!("{}:0", f.tokens[0].txid));
        assert_token_sigs_cover(&f, &broadcast);
    }
}

#[test]
fn merge_spends_both_token_utxos_signed_over_the_broadcast_tx() {
    let art = artifact();
    // Second case: token UTXOs larger than the funding coin — funding
    // selection must not also pick the second token UTXO as a P2PKH input.
    for (token_sats, funding_sats) in [(5_000, 200_000), (300_000, 50_000)] {
        let mut f = setup(&art, &[100, 250], token_sats, funding_sats);
        f.wallet.merge().expect("merge");
        let broadcast = f.provider.borrow().get_broadcasted_txs().last().unwrap().clone();
        let spent = outpoints(&broadcast);
        let mut seen: HashMap<String, usize> = HashMap::new();
        for s in &spent { *seen.entry(s.clone()).or_default() += 1; }
        for u in &f.tokens {
            assert_eq!(seen.get(&format!("{}:0", u.txid)), Some(&1), "token {} not spent exactly once: {:?}", u.txid, spent);
        }
        assert_eq!(seen.len(), spent.len(), "an outpoint is spent twice: {:?}", spent);
        assert_token_sigs_cover(&f, &broadcast);
        let tx = hex_to_bsv_tx(&broadcast).unwrap();
        let merged = RunarContract::from_utxo(art.clone(), &Utxo {
            txid: "00".repeat(32), output_index: 0,
            satoshis: tx.outputs[0].satoshis.unwrap() as i64, script: tx.outputs[0].locking_script.to_hex(),
        }).unwrap();
        assert!(matches!(merged.state().get("supply"), Some(SdkValue::Int(350))), "{:?}", merged.state());
    }
}
