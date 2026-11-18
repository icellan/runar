//! D12 SDK-F1 / SDK-F2 / SDK-F3.
//!
//! prepare_call never leaves the tracked state changed: it derives the
//! post-call state into the PreparedCall and restores `self.state` before it
//! returns, on success AND on error. finalize_call commits the post-call state
//! only after a successful broadcast. An abandoned PreparedCall needs no
//! cleanup.
//!
//! The Rust MockProvider cannot run a push-tx covenant (OP_2MUL), so these
//! tests assert SDK state, not interpreter verdicts.

use std::collections::HashMap;
use std::sync::Arc;

use bsv::transaction::Transaction as BsvTransaction;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::{CallOptions, FundingSigner, RunarArtifact};
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

struct Flaky {
    inner: MockProvider,
    fail_utxos: bool,
    fail_fee_rate: bool,
    refuse: bool,
}

impl Provider for Flaky {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        self.inner.get_transaction(txid)
    }
    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        if self.refuse {
            return Err("node refused the transaction".into());
        }
        self.inner.broadcast(tx)
    }
    fn get_utxos(&self, address: &str) -> Result<Vec<Utxo>, String> {
        if self.fail_utxos {
            return Err("ECONNRESET".into());
        }
        self.inner.get_utxos(address)
    }
    fn get_contract_utxo(&self, script_hash: &str) -> Result<Option<Utxo>, String> {
        self.inner.get_contract_utxo(script_hash)
    }
    fn get_network(&self) -> &str {
        self.inner.get_network()
    }
    fn get_fee_rate(&self) -> Result<i64, String> {
        if self.fail_fee_rate {
            return Err("503".into());
        }
        self.inner.get_fee_rate()
    }
    fn get_raw_transaction(&self, txid: &str) -> Result<String, String> {
        self.inner.get_raw_transaction(txid)
    }
}

struct Declining(LocalSigner);

impl Signer for Declining {
    fn get_public_key(&self) -> Result<String, String> {
        self.0.get_public_key()
    }
    fn get_address(&self) -> Result<String, String> {
        self.0.get_address()
    }
    fn sign(&self, _: &str, _: usize, _: &str, _: i64, _: Option<u32>) -> Result<String, String> {
        Err("user declined".into())
    }
}

fn key() -> String {
    "11".repeat(32)
}

fn deploy_gate() -> (RunarContract, Flaky, LocalSigner) {
    let signer = LocalSigner::new(&key()).unwrap();
    let address = signer.get_address().unwrap();
    let mut mock = MockProvider::testnet();
    mock.add_utxo(&address, Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000_000, script: build_p2pkh_script(&address) });
    let mut provider = Flaky { inner: mock, fail_utxos: false, fail_fee_rate: false, refuse: false };
    let mut contract = RunarContract::new(artifact(), vec![SdkValue::Int(0)]);
    contract
        .deploy(&mut provider, &signer, &DeployOptions { satoshis: 50_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] })
        .expect("deploy");
    (contract, provider, signer)
}

fn n(c: &RunarContract) -> SdkValue {
    c.state().get("n").cloned().expect("n")
}

fn check_failed_prepare_leaves_state(arm: impl Fn(&mut Flaky) -> Option<CallOptions>, label: &str) {
    let (mut contract, mut provider, signer) = deploy_gate();
    let opts = arm(&mut provider);
    let r = contract.call("bump", &[SdkValue::Int(7)], &mut provider, &signer, opts.as_ref());
    assert!(r.is_err(), "{}: call must fail, got {:?}", label, r.map(|x| x.0));
    assert_eq!(n(&contract), SdkValue::Int(0), "{}: state must stay at the chain's n = 0", label);
    provider.fail_utxos = false;
    provider.fail_fee_rate = false;
    contract.call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None).expect("follow-up");
    assert_eq!(n(&contract), SdkValue::Int(1), "{}: follow-up must commit n = 1", label);
}

#[test]
fn d12_prepare_call_fee_rate_error_leaves_state() {
    check_failed_prepare_leaves_state(|p| { p.fail_fee_rate = true; None }, "get_fee_rate");
}

/// SDK-F3: a get_utxos failure must propagate as an error, not become
/// "no funding" and a zero-fee spend that returns Ok.
#[test]
fn d12_prepare_call_get_utxos_error_propagates() {
    check_failed_prepare_leaves_state(|p| { p.fail_utxos = true; None }, "get_utxos");
}

#[test]
fn d12_prepare_call_funding_signer_declines_leaves_state() {
    check_failed_prepare_leaves_state(
        |_| {
            let s: Arc<dyn Signer> = Arc::new(Declining(LocalSigner::new(&key()).unwrap()));
            Some(CallOptions { funding_signer: Some(FundingSigner(s)), ..Default::default() })
        },
        "funding signer",
    );
}

#[test]
fn d12_prepare_call_max_funding_inputs_zero_leaves_state() {
    check_failed_prepare_leaves_state(
        |_| Some(CallOptions { max_funding_inputs: Some(0), ..Default::default() }),
        "max_funding_inputs",
    );
}

/// SDK-F2: abandoned and superseded PreparedCalls.
#[test]
fn d12_abandoned_and_superseded_prepared_call() {
    let (mut contract, mut provider, signer) = deploy_gate();
    let no_sigs: HashMap<usize, String> = HashMap::new();

    contract.prepare_call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None).expect("prepare");
    assert_eq!(n(&contract), SdkValue::Int(0), "an abandoned prepare_call must not advance state");

    let a = contract.prepare_call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None).expect("A");
    let b = contract.prepare_call("bump", &[SdkValue::Int(7)], &mut provider, &signer, None).expect("B");
    assert_eq!(n(&contract), SdkValue::Int(0));

    provider.refuse = true;
    assert!(contract.finalize_call(&b, &no_sigs, &mut provider).is_err());
    assert_eq!(n(&contract), SdkValue::Int(0));
    provider.refuse = false;
    contract.finalize_call(&a, &no_sigs, &mut provider).expect("finalize A");
    assert_eq!(n(&contract), SdkValue::Int(1));
    provider.refuse = true;
    assert!(contract.finalize_call(&b, &no_sigs, &mut provider).is_err());
    assert_eq!(n(&contract), SdkValue::Int(1), "a failed stale finalize must not rewind A's commit");
}
