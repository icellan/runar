//! D25 (D12 PRE-F1) — twin-input binding, Rust SDK side.
//!
//! The compiler binds every state continuation to the input that made it
//! (compilers/rust/src/frontend/continuation_binding.rs):
//!
//!   class 1  every continuation method mutate-only (Counter) -> the method
//!            commits under SIGHASH_SINGLE|FORKID: hashOutputs covers
//!            output[inputIndex] alone, the method takes `_newAmount,
//!            txPreimage` (no change params), change after it is uncommitted.
//!   class 2  auto-continuation mixed with addOutput (MixedPot) -> a hidden
//!            last state field `_spentOutpointHash` = sha256(spent outpoint),
//!            zero at deploy, written by every continuation.
//!
//! What this proves, for honest call() chains through the default validating
//! MockProvider: each broadcast call carries the covenant preimage under the
//! method's mode, the continuation at output 0 equals the independently
//! rebuilt `codePart || OP_RETURN || state` (with the binding of the REAL
//! spent outpoint for class 2), and the preimage's hashOutputs is exactly the
//! hash the covenant reconstructs (output 0 alone under SINGLE; continuation
//! || change under ALL). It also pins the SINGLE refusal of
//! `additional_contract_inputs` (TS text) and the post-call state.
//!
//! For class 2 it also builds the twin with the SDK's own
//! `additional_contract_inputs` merge and shows output 0 binds input 0 only.
//!
//! What it does NOT prove: on-chain execution of the covenant. The Rust tier's
//! Spend (bsv-sdk) refuses the OP_2MUL every OP_PUSH_TX covenant emits, so
//! the covenant input is counted as UNVALIDATABLE (asserted below; only the
//! P2PKH funding input really runs). The executed twin attacks live in the TS
//! tier
//! (packages/runar-sdk/src/__tests__/d25-twin-input.test.ts).

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{CallOptions, DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";
const FIELD: &str = "_spentOutpointHash";

const MIXED_SRC: &str = r#"
import { StatefulSmartContract, assert, extractAmount } from 'runar-lang';

class MixedPot extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public increment() {
    this.count++;
  }

  public bump() {
    this.addOutput(extractAmount(this.txPreimage), this.count + 1n);
  }
}
"#;

fn artifact(src: &str, name: &str) -> RunarArtifact {
    let a = runar_compiler_rust::compile_from_source_str(src, Some(name)).expect("compile");
    serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap()
}

fn counter_artifact() -> RunarArtifact {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/ts/stateful-counter/Counter.runar.ts"),
    )
    .unwrap();
    artifact(&src, "Counter.runar.ts")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn sha256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}
fn hash256(b: &[u8]) -> Vec<u8> {
    sha256(&sha256(b))
}

fn varint(b: &[u8], p: &mut usize) -> usize {
    let f = b[*p];
    *p += 1;
    let n = match f {
        0xfd => 2,
        0xfe => 4,
        0xff => 8,
        x => return x as usize,
    };
    let v = (0..n).map(|i| (b[*p + i] as usize) << (8 * i)).sum();
    *p += n;
    v
}

struct Tx {
    /// (outpoint wire bytes = txid LE || vout LE, unlocking script)
    inputs: Vec<(Vec<u8>, Vec<u8>)>,
    /// serialized outputs (8-byte value || varint || script) and (sats, script)
    outputs: Vec<(Vec<u8>, i64, String)>,
}

fn parse_tx(hex: &str) -> Tx {
    let b = unhex(hex);
    let mut p = 4;
    let mut inputs = Vec::new();
    for _ in 0..varint(&b, &mut p) {
        let op = b[p..p + 36].to_vec();
        p += 36;
        let n = varint(&b, &mut p);
        inputs.push((op, b[p..p + n].to_vec()));
        p += n + 4;
    }
    let mut outputs = Vec::new();
    for _ in 0..varint(&b, &mut p) {
        let start = p;
        let sats = (0..8).map(|i| (b[p + i] as i64) << (8 * i)).sum();
        p += 8;
        let n = varint(&b, &mut p);
        let script = tohex(&b[p..p + n]);
        p += n;
        outputs.push((b[start..p].to_vec(), sats, script));
    }
    Tx { inputs, outputs }
}

/// Every data push of a push-only script.
fn pushes(s: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let op = s[i] as usize;
        i += 1;
        let n = match op {
            0x01..=0x4b => op,
            0x4c => {
                i += 1;
                s[i - 1] as usize
            }
            0x4d => {
                i += 2;
                s[i - 2] as usize | (s[i - 1] as usize) << 8
            }
            0x4e => {
                i += 4;
                (0..4).map(|k| (s[i - 4 + k] as usize) << (8 * k)).sum()
            }
            _ => 0,
        };
        out.push(s[i..i + n].to_vec());
        i += n;
    }
    out
}

/// The BIP-143 preimage pushed in a covenant unlock (version 1 ... sighash type).
fn pushed_preimage(unlock: &[u8]) -> Vec<u8> {
    pushes(unlock)
        .into_iter()
        .filter(|p| p.len() >= 156 && p[..4] == [1, 0, 0, 0] && p[p.len() - 3..] == [0, 0, 0])
        .last()
        .expect("the unlock pushes a BIP-143 preimage")
}

/// The continuation locking script the covenant rebuilds for `state`.
fn next_script(art: &RunarArtifact, state: &[(&str, SdkValue)]) -> String {
    let mut c = RunarContract::new(art.clone(), vec![SdkValue::Int(0)]);
    c.set_state(state.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<HashMap<_, _>>());
    c.get_locking_script()
}

fn setup(art: RunarArtifact) -> (RunarContract, MockProvider, LocalSigner) {
    let signer = LocalSigner::new(KEY).unwrap();
    let address = signer.get_address().unwrap();
    let mut provider = MockProvider::testnet();
    for k in 0..4u8 {
        provider.add_utxo(
            &address,
            Utxo {
                txid: format!("{:02x}", 0xa0 + k).repeat(32),
                output_index: k as u32,
                satoshis: 500_000,
                script: build_p2pkh_script(&address),
            },
        );
    }
    let mut c = RunarContract::new(art, vec![SdkValue::Int(0)]);
    c.deploy(
        &mut provider,
        &signer,
        &DeployOptions { satoshis: 10_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] },
    )
    .expect("deploy");
    (c, provider, signer)
}

/// One honest call; returns (the spent UTXO, the broadcast tx, the pushed preimage).
fn call(c: &mut RunarContract, p: &mut MockProvider, s: &LocalSigner, m: &str) -> (Utxo, Tx, Vec<u8>) {
    let spent = c.get_utxo().unwrap().clone();
    c.call(m, &[], p, s, None).unwrap_or_else(|e| panic!("call {m}: {e}"));
    let tx = parse_tx(p.get_broadcasted_txs().last().unwrap());
    let r = p.last_validation_report().clone();
    assert!(r.validated >= 1, "{m}: the P2PKH funding input must really execute: {r:?}");
    assert_eq!(r.unvalidatable, 1, "{m}: the covenant input is the one bsv-sdk cannot run (OP_2MUL): {r:?}");
    let pre = pushed_preimage(&tx.inputs[0].1);
    // The preimage is input 0's, and input 0 spends the tracked contract UTXO.
    let mut op = unhex(&spent.txid);
    op.reverse();
    op.extend_from_slice(&spent.output_index.to_le_bytes());
    assert_eq!(tx.inputs[0].0, op, "{m}: input 0 spends the contract UTXO");
    assert_eq!(pre[68..104], op[..], "{m}: the preimage carries input 0's outpoint");
    (spent, tx, pre)
}

fn hash_outputs(pre: &[u8]) -> &[u8] {
    &pre[pre.len() - 40..pre.len() - 8]
}

fn outpoint_hash(u: &Utxo) -> String {
    let mut op = unhex(&u.txid);
    op.reverse();
    op.extend_from_slice(&u.output_index.to_le_bytes());
    tohex(&sha256(&op))
}

// ---- class 1 ---------------------------------------------------------------

#[test]
fn class1_counter_honest_chain_commits_each_continuation_under_single() {
    let art = counter_artifact();
    for m in ["increment", "decrement"] {
        let abi = art.abi.methods.iter().find(|x| x.name == m).unwrap();
        assert_eq!(abi.sig_hash_type, Some(0x43), "{m}");
        let ps: Vec<&str> = abi.params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(ps, vec!["_newAmount", "txPreimage"], "{m}");
    }
    let (mut c, mut p, s) = setup(art.clone());
    let mut count = 0i64;
    for m in ["increment", "increment", "decrement"] {
        let (spent, tx, pre) = call(&mut c, &mut p, &s, m);
        count += if m == "decrement" { -1 } else { 1 };
        assert_eq!(&pre[pre.len() - 4..], &[0x43, 0, 0, 0], "{m}: covenant preimage under SINGLE|FORKID");
        // The continuation is at output 0 (== the contract's input index), at
        // no less than the input value (F-024 floor), with the rebuilt state.
        let (ser0, sats0, script0) = &tx.outputs[0];
        assert_eq!(script0, &next_script(&art, &[("count", SdkValue::Int(count))]), "{m}");
        assert!(*sats0 >= spent.satoshis, "{m}: continuation value below the input");
        // SINGLE: hashOutputs is hash256(output[inputIndex]) alone; the change
        // after it is not committed.
        assert!(tx.outputs.len() >= 2, "{m}: a funded call carries change after the continuation");
        assert_eq!(hash_outputs(&pre), &hash256(ser0)[..], "{m}");
        let all: Vec<u8> = tx.outputs.iter().flat_map(|o| o.0.clone()).collect();
        assert_ne!(hash_outputs(&pre), &hash256(&all)[..], "{m}: change must not be committed");
    }
    assert_eq!(c.state().get("count"), Some(&SdkValue::Int(1)));
}

#[test]
fn class1_additional_contract_inputs_into_one_single_continuation_are_refused() {
    let art = counter_artifact();
    let (mut c, mut p, s) = setup(art.clone());
    let other = Utxo {
        txid: "c1".repeat(32),
        output_index: 1,
        satoshis: 10_000,
        script: next_script(&art, &[("count", SdkValue::Int(0))]),
    };
    let opts = CallOptions { additional_contract_inputs: Some(vec![other]), ..Default::default() };
    let before = p.get_broadcasted_txs().len();
    let err = c.call("increment", &[], &mut p, &s, Some(&opts)).expect_err("a SINGLE merge must be refused");
    assert_eq!(
        err,
        "RunarContract.call(increment): additionalContractInputs cannot be spent into one continuation by a \
SIGHASH_SINGLE method (the default for a contract whose continuation methods are all mutate-only, D25): \
SINGLE commits each input to its own output at its own index. Merge with an addOutput method instead (see \
FungibleToken.merge), or build each input's continuation with assembleMultiContractCall"
    );
    assert_eq!(p.get_broadcasted_txs().len(), before, "nothing broadcast");
}

// ---- class 2 ---------------------------------------------------------------

#[test]
fn class2_mixedpot_honest_chain_binds_each_continuation_to_its_spent_outpoint() {
    let art = artifact(MIXED_SRC, "MixedPot.runar.ts");
    let fields: Vec<&str> = art.state_fields.as_ref().unwrap().iter().map(|f| f.name.as_str()).collect();
    assert_eq!(fields, vec!["count", FIELD]);
    let ctor: Vec<&str> = art.abi.constructor.params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(ctor, vec!["count"]);
    for m in ["increment", "bump"] {
        assert_eq!(art.abi.methods.iter().find(|x| x.name == m).unwrap().sig_hash_type, None, "{m} stays ALL");
    }

    let (mut c, mut p, s) = setup(art.clone());
    // Zero at deploy (the artifact's initialValue), not a constructor arg.
    let deployed = c.get_utxo().unwrap().script.clone();
    // State is raw fixed-width after OP_RETURN: count (8 bytes) || binding (32 bytes).
    assert!(
        deployed.ends_with(&format!("6a{}{}", "00".repeat(8), "00".repeat(32))),
        "deploy carries a zero binding: ...{}",
        &deployed[deployed.len().saturating_sub(100)..]
    );

    let mut count = 0i64;
    for m in ["increment", "bump", "increment"] {
        let (spent, tx, pre) = call(&mut c, &mut p, &s, m);
        count += 1;
        assert_eq!(&pre[pre.len() - 4..], &[0x41, 0, 0, 0], "{m}: covenant preimage under ALL|FORKID");
        let binding = outpoint_hash(&spent);
        let (_, sats0, script0) = &tx.outputs[0];
        assert_eq!(
            script0,
            &next_script(&art, &[("count", SdkValue::Int(count)), (FIELD, SdkValue::Bytes(binding.clone()))]),
            "{m}: continuation carries sha256 of the REAL spent outpoint"
        );
        assert!(script0.ends_with(&binding), "{m}: the binding is the LAST state field");
        if m == "bump" {
            assert_eq!(*sats0, spent.satoshis, "{m}: addOutput(extractAmount) re-creates the input value");
        }
        // ALL: hashOutputs covers continuation || change (the whole list).
        let all: Vec<u8> = tx.outputs.iter().flat_map(|o| o.0.clone()).collect();
        assert_eq!(hash_outputs(&pre), &hash256(&all)[..], "{m}");
        assert_eq!(c.state().get(FIELD), Some(&SdkValue::Bytes(binding)), "{m}: tracked state");
    }
    assert_eq!(c.state().get("count"), Some(&SdkValue::Int(3)));
}

/// Class 2 twin: the SDK's own many-to-one shape (`additional_contract_inputs`)
/// spends two MixedPot(0) UTXOs into ONE count=1 continuation. Before D25 both
/// inputs rebuilt the same output list and both verified. With the binding,
/// output 0 carries sha256(input 0's outpoint), so input 1's covenant — which
/// rebuilds its continuation with sha256(input 1's outpoint) — cannot match.
///
/// Proves (structurally, in-tier): the two inputs' preimages name different
/// outpoints and output 0 binds input 0's only, so the continuation input 1's
/// covenant rebuilds (asserted unequal here) is absent from the tx. Does NOT
/// prove execution: neither covenant input can run on this tier's bsv-sdk
/// Spend (OP_2MUL), which the report below records (both unvalidatable).
#[test]
fn class2_twin_via_additional_contract_inputs_cannot_satisfy_the_second_input() {
    let art = artifact(MIXED_SRC, "MixedPot.runar.ts");
    let (mut c, mut p, s) = setup(art.clone());
    let primary = c.get_utxo().unwrap().clone();
    let twin = Utxo { txid: "d2".repeat(32), output_index: 3, satoshis: primary.satoshis, script: primary.script.clone() };
    p.add_contract_utxo(&twin.script.clone(), twin.clone());

    let opts = CallOptions { additional_contract_inputs: Some(vec![twin.clone()]), ..Default::default() };
    let res = c.call("increment", &[], &mut p, &s, Some(&opts));
    let tx = parse_tx(p.get_broadcasted_txs().last().unwrap());
    let r = p.last_validation_report().clone();
    assert!(res.is_ok(), "the SDK builds the merge: {res:?}");
    assert_eq!(r.unvalidatable, 2, "neither covenant input can run on bsv-sdk Spend here: {r:?}");

    let pre0 = pushed_preimage(&tx.inputs[0].1);
    let pre1 = pushed_preimage(&tx.inputs[1].1);
    assert_eq!(pre0[68..104], tx.inputs[0].0[..]);
    assert_eq!(pre1[68..104], tx.inputs[1].0[..]);
    assert_ne!(pre0[68..104], pre1[68..104], "the two inputs spend different outpoints");

    let cont = |u: &Utxo| next_script(&art, &[("count", SdkValue::Int(1)), (FIELD, SdkValue::Bytes(outpoint_hash(u)))]);
    assert_eq!(tx.outputs[0].2, cont(&primary), "output 0 is bound to input 0");
    assert_ne!(cont(&twin), cont(&primary), "input 1's covenant rebuilds a different continuation");
    assert!(
        tx.outputs.iter().all(|o| o.2 != cont(&twin)),
        "no output carries input 1's continuation, so its hashOutputs check cannot pass"
    );
}
