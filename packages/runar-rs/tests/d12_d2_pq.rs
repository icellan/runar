//! D12 D2: extractLocktime / extractSequence / extractOutpoint read the REAL
//! fields of the call transaction during `prepare_call`'s state derivation,
//! not the 0 / 0xfffffffe / 36-zero-byte dummies.
//! D12 PQ-F1: a constructor arg flowing straight into verifyWOTS /
//! verifySLHDSA_* as the public key must have the parameter set's length.
//! The check reads the artifact's ANF, which the compilers emit for stateful
//! contracts only, so stateful contracts are used here.
//!
//! The Rust MockProvider cannot run push-tx covenants, so D2 asserts the
//! derived state against the tx the SDK built (its locktime, input 0's
//! sequence and outpoint), which is what the script reads.


use bsv::transaction::Transaction as BsvTransaction;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::{CallOptions, RunarArtifact};
use runar_lang::sdk::{DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer};

fn compile(src: &str, name: &str) -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(src, Some(name)).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

#[test]
fn d12_d2_preimage_extractors_use_real_tx_fields() {
    let art = compile(
        r#"
class Rec extends StatefulSmartContract {
  lt: bigint;
  sq: bigint;
  op: ByteString;
  constructor(lt: bigint, sq: bigint, op: ByteString) { super(lt, sq, op); this.lt = lt; this.sq = sq; this.op = op; }
  public rec() {
    this.lt = extractLocktime(this.txPreimage);
    this.sq = extractSequence(this.txPreimage);
    this.op = extractOutpoint(this.txPreimage);
  }
}
"#,
        "Rec.runar.ts",
    );
    let signer = LocalSigner::new(&"11".repeat(32)).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    provider.add_utxo(&address, runar_lang::sdk::Utxo { txid: "aa".repeat(32), output_index: 0, satoshis: 5_000_000, script: build_p2pkh_script(&address) });
    let mut c = RunarContract::new(art, vec![SdkValue::Int(0), SdkValue::Int(0), SdkValue::Bytes(String::new())]);
    c.deploy(&mut provider, &signer, &DeployOptions { satoshis: 50_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] })
        .expect("deploy");
    for (locktime, sequence) in [(None, None), (Some(100u32), None), (Some(100u32), Some(7u32))] {
        let spent = c.get_utxo().cloned().unwrap();
        let opts = CallOptions { locktime, sequence, ..Default::default() };
        let prepared = c.prepare_call("rec", &[], &mut provider, &signer, Some(&opts)).expect("prepare");
        let tx = BsvTransaction::from_hex(&prepared.tx_hex).expect("tx");
        let seq0 = tx.inputs[0].sequence;
        let lt = tx.lock_time;
        c.finalize_call(&prepared, &std::collections::HashMap::new(), &mut provider).expect("finalize");
        let mut txid_le: Vec<u8> = (0..spent.txid.len()).step_by(2)
            .map(|i| u8::from_str_radix(&spent.txid[i..i + 2], 16).unwrap()).collect();
        txid_le.reverse();
        txid_le.extend_from_slice(&spent.output_index.to_le_bytes());
        let want_op: String = txid_le.iter().map(|b| format!("{:02x}", b)).collect();
        let label = format!("locktime={:?} sequence={:?}", locktime, sequence);
        assert_eq!(c.state().get("lt"), Some(&SdkValue::Int(lt as i64)), "{}", label);
        assert_eq!(c.state().get("sq"), Some(&SdkValue::Int(seq0 as i64)), "{}", label);
        assert_eq!(c.state().get("op"), Some(&SdkValue::Bytes(want_op)), "{}", label);
    }
}

fn must_refuse(label: &str, f: impl FnOnce() + std::panic::UnwindSafe) {
    assert!(std::panic::catch_unwind(f).is_err(), "{}: accepted, want a refusal", label);
}

#[test]
fn d12_pq_f1_pubkey_length_checked_at_construction() {
    let wots = compile(
        r#"
class W extends StatefulSmartContract {
  readonly pubkey: ByteString;
  n: bigint;
  constructor(pubkey: ByteString, n: bigint) { super(pubkey, n); this.pubkey = pubkey; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifyWOTS(msg, sig, this.pubkey)); this.n = this.n + 1n; }
}
"#,
        "W.runar.ts",
    );
    for n in [0usize, 32, 63, 65, 128] {
        let a = wots.clone();
        must_refuse(&format!("WOTS pk {} B", n), move || {
            RunarContract::new(a, vec![SdkValue::Bytes("01".repeat(n)), SdkValue::Int(0)]);
        });
    }
    RunarContract::new(wots, vec![SdkValue::Bytes("01".repeat(64)), SdkValue::Int(0)]);

    let slh = compile(
        r#"
class S extends StatefulSmartContract {
  readonly pubkey: ByteString;
  n: bigint;
  constructor(pubkey: ByteString, n: bigint) { super(pubkey, n); this.pubkey = pubkey; this.n = n; }
  public spend(msg: ByteString, sig: ByteString) { assert(verifySLHDSA_SHA2_192f(msg, sig, this.pubkey)); this.n = this.n + 1n; }
}
"#,
        "S.runar.ts",
    );
    for n in [0usize, 32, 47, 49, 64] {
        let a = slh.clone();
        must_refuse(&format!("SLH-DSA-192f pk {} B", n), move || {
            RunarContract::new(a, vec![SdkValue::Bytes("01".repeat(n)), SdkValue::Int(0)]);
        });
    }
    RunarContract::new(slh, vec![SdkValue::Bytes("01".repeat(48)), SdkValue::Int(0)]);
}
