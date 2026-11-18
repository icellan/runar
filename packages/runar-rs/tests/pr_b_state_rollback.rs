//! `prepare_call` advances the contract's local state to the post-call state
//! BEFORE `finalize_call` broadcasts. When the broadcast was refused nothing
//! put it back, so the next call was built from a state the chain never
//! reached (same bug as the TS SDK,
//! packages/runar-sdk/src/__tests__/pr-b-state-rollback.test.ts).
//!
//! The Rust MockProvider cannot execute a push-tx covenant (bsv-sdk's
//! pre-Chronicle policy refuses OP_2MUL, so the input is counted
//! "unvalidatable"), so it would not refuse `bump(8)` on its own. The refusal
//! comes from a provider whose `broadcast()` errors once, like a node that
//! rejects the transaction.
//!
//! Proves: after a failed broadcast, `state()` and `get_utxo()` equal their
//! pre-call values, and an honest follow-up call commits n = 1.

use std::collections::HashMap;

use bsv::transaction::Transaction as BsvTransaction;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, Provider, RunarContract, SdkValue, Signer,
    TransactionData, Utxo,
};

const SRC: &str = r#"
class Gate extends StatefulSmartContract {
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(k: bigint) {
    assert(k === 7n);
    this.n = this.n + 1n;
  }
}
"#;

fn artifact() -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(SRC, Some("Gate.runar.ts")).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

/// Delegates to a validating `MockProvider`, except that `broadcast()` errors
/// while `refuse` is set.
struct RefusingProvider {
    inner: MockProvider,
    refuse: bool,
}

impl Provider for RefusingProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        self.inner.get_transaction(txid)
    }
    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        if self.refuse {
            return Err("node refused the transaction (mandatory-script-verify-flag-failed)".into());
        }
        self.inner.broadcast(tx)
    }
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        self.inner.get_utxos(address)
    }
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        self.inner.get_contract_utxo(script_hash)
    }
    fn get_network(&self) -> &str {
        self.inner.get_network()
    }
    fn get_fee_rate(&self) -> Result<i64, String> {
        self.inner.get_fee_rate()
    }
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        self.inner.get_raw_transaction(txid)
    }
}

fn deploy_gate() -> (RunarContract, RefusingProvider, LocalSigner) {
    let signer = LocalSigner::new(&"11".repeat(32)).unwrap();
    let address = signer.get_address().unwrap();
    let mut mock = MockProvider::testnet();
    mock.add_utxo(&address, Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000_000, script: build_p2pkh_script(&address) });
    let mut provider = RefusingProvider { inner: mock, refuse: false };

    let mut contract = RunarContract::new(artifact(), vec![SdkValue::Int(0)]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions { satoshis: 50_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] })
        .expect("deploy");
    (contract, provider, signer)
}

fn utxo_key(c: &RunarContract) -> (String, u32, i64, String) {
    let u = c.get_utxo().cloned().expect("tracked utxo");
    (u.txid, u.output_index, u.satoshis, u.script)
}

#[test]
fn pr_b_state_rollback_refused_broadcast_leaves_state_untouched() {
    let (mut contract, mut provider, signer) = deploy_gate();
    let state_before = contract.state().clone();
    let utxo_before = contract.get_utxo().cloned().expect("deployed utxo");

    provider.refuse = true;
    let err = contract.call("bump", &[SdkValue::Int(8)], &mut provider, &signer, None);
    assert!(err.is_err(), "bump(8) must fail: the broadcast was refused");
    assert_eq!(contract.state(), &state_before, "state must be unchanged after a refused broadcast");
    let utxo_after = contract.get_utxo().cloned().expect("tracked utxo");
    assert_eq!(
        (utxo_after.txid, utxo_after.output_index, utxo_after.satoshis, utxo_after.script),
        (utxo_before.txid, utxo_before.output_index, utxo_before.satoshis, utxo_before.script),
        "tracked UTXO must be unchanged after a refused broadcast"
    );

    provider.refuse = false;
    contract.call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None).expect("bump(7)");
    assert_eq!(contract.state().get("n"), Some(&SdkValue::Int(1)), "{:?}", contract.state());
}

/// A PreparedCall whose broadcast was refused can be finalized again: the
/// retry commits the post-call state. A further finalize of the now-committed
/// PreparedCall that fails must not rewind the state the chain reached.
#[test]
fn pr_b_state_rollback_retried_and_repeated_finalize() {
    let (mut contract, mut provider, signer) = deploy_gate();
    let utxo_before = utxo_key(&contract);
    let no_sigs: HashMap<usize, String> = HashMap::new();

    let prepared = contract
        .prepare_call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None)
        .expect("prepare bump(7)");
    provider.refuse = true;
    assert!(contract.finalize_call(&prepared, &no_sigs, &mut provider).is_err());
    assert_eq!(contract.state().get("n"), Some(&SdkValue::Int(0)), "{:?}", contract.state());
    assert_eq!(utxo_key(&contract), utxo_before);

    provider.refuse = false;
    contract.finalize_call(&prepared, &no_sigs, &mut provider).expect("retried finalize");
    assert_eq!(contract.state().get("n"), Some(&SdkValue::Int(1)), "{:?}", contract.state());
    let utxo_after = utxo_key(&contract);

    provider.refuse = true;
    assert!(contract.finalize_call(&prepared, &no_sigs, &mut provider).is_err());
    assert_eq!(
        contract.state().get("n"),
        Some(&SdkValue::Int(1)),
        "a refused repeat of a committed finalize must not rewind state: {:?}",
        contract.state()
    );
    assert_eq!(utxo_key(&contract), utxo_after);
}
