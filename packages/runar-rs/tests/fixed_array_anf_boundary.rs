//! FixedArray state across the ANF-interpreter boundary (call path).
//!
//! Pass `03b-expand-fixed-arrays` runs BEFORE ANF lowering, so the ANF program
//! has no property called `table` at all — it has `table__0`..`table__3`, and
//! every `load_prop` / `update_prop` in the method body names one of those. The
//! SDK's user-facing `state` map, by contrast, is keyed by the GROUPED name.
//! Both directions of that boundary have to be bridged or the continuation
//! output commits a state the method did not compute.
//!
//! The sharp probe is the RECONNECT path: `from_utxo` sets `state` to exactly
//! what `deserialize_state` decodes off chain, which for a FixedArray field is
//! the grouped entry and nothing else — no synthetic leaves to mask an
//! unbridged inbound boundary. Because `self.table[i] += 1` at a runtime index
//! lowers to a per-leaf select, an absent property makes the interpreter fall
//! back to each leaf's ANF `initialValue` and rewrite ALL FOUR leaves from it,
//! so the continuation commits the deploy-time array and the covenant's
//! hashOutputs binding rejects the spend.
//!
//! Fixture: `examples/rust/fixed-array-write/ArrayWrite.runar.rs` —
//! `table: FixedArray<bigint, 4> = [0,0,0,0]`, `bump(i)` doing
//! `self.table[i] += 1`. Checked in at `tests/fixtures/arraywrite-artifact.json`,
//! compiled with `--ir` so the artifact carries the ANF the call path needs.
//!
//! Every case runs on the DEFAULT validating `MockProvider` with a real
//! `LocalSigner`. As documented in `tests/g1_raw_outputs_spend.rs`, bsv-sdk's
//! `Spend` cannot validate ANY Rúnar OP_PUSH_TX covenant (pre-Chronicle opcode
//! policy hard-disables the `OP_2MUL` the low-S normalisation emits), so the
//! load-bearing assertion here is the continuation BYTES: the 32-byte state
//! section the next spend is bound to.

use std::path::Path;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};

const DEPLOYER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";

fn load_artifact() -> RunarArtifact {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/arraywrite-artifact.json");
    let raw = std::fs::read_to_string(&path).expect("reading the ArrayWrite artifact");
    let artifact: RunarArtifact =
        serde_json::from_str(&raw).expect("deserializing the ArrayWrite artifact");
    // Without ANF the call path never reaches the interpreter and this whole
    // file would be vacuous.
    assert!(
        artifact.anf.is_some(),
        "ArrayWrite artifact carries no ANF; the call path would never reach the interpreter"
    );
    artifact
}

/// Little-endian 8-byte words, one per leaf — the contract's state bytes.
fn le_hex(vals: &[i64]) -> String {
    vals.iter()
        .map(|v| {
            v.to_le_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect()
}

/// The 32-byte state section after the final OP_RETURN of a locking script.
fn state_tail_hex(script_hex: &str) -> &str {
    const NIBBLES: usize = 4 * 8 * 2;
    assert!(
        script_hex.len() > NIBBLES + 2,
        "locking script too short to carry a 32-byte state section: {} bytes",
        script_hex.len() / 2
    );
    let start = script_hex.len() - NIBBLES;
    assert_eq!(
        &script_hex[start - 2..start],
        "6a",
        "expected OP_RETURN (6a) before the 32-byte state section"
    );
    &script_hex[start..]
}

/// The user-facing grouped state entry, as i64s.
fn grouped_table(contract: &RunarContract) -> Vec<i64> {
    match contract.state().get("table") {
        Some(SdkValue::Array(items)) => items
            .iter()
            .map(|v| match v {
                SdkValue::Int(n) => *n,
                other => panic!("grouped `table` leaf is {:?}, want an Int", other),
            })
            .collect(),
        other => panic!("state has no grouped `table` array: {:?}", other),
    }
}

fn deploy_array_write() -> (RunarContract, MockProvider, LocalSigner) {
    let signer = LocalSigner::new(DEPLOYER_KEY).unwrap();
    let mut provider = MockProvider::testnet();
    let address = signer.get_address().unwrap();
    provider.add_utxo(
        &address,
        Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 1_000_000,
            script: build_p2pkh_script(&address),
        },
    );

    let mut contract = RunarContract::new(load_artifact(), vec![]);
    contract
        .deploy(
            &mut provider,
            &signer,
            &DeployOptions {
                satoshis: 50_000,
                change_address: None,
                funding_signer: None,
                acknowledge_unsound: vec![],
            },
        )
        .expect("deploy should succeed");
    (contract, provider, signer)
}

/// OUTBOUND: the post-call state the interpreter computed under the SYNTHETIC
/// leaf names has to reach BOTH the continuation output's state section and the
/// grouped user-facing `table` entry. `serialize_state` reads a FixedArray field
/// from its GROUPED entry only, so a stale grouped entry is not merely a state
/// lie — it is the wire bytes.
#[test]
fn outbound_continuation_and_grouped_entry_carry_the_computed_state() {
    let (mut contract, mut provider, signer) = deploy_array_write();

    assert_eq!(
        state_tail_hex(&contract.get_utxo().unwrap().script),
        le_hex(&[0, 0, 0, 0])
    );

    contract
        .call("bump", &[SdkValue::Int(0)], &mut provider, &signer, None)
        .expect("call(bump, 0) should succeed");

    assert_eq!(
        state_tail_hex(&contract.get_utxo().unwrap().script),
        le_hex(&[1, 0, 0, 0]),
        "the continuation committed a state the method did not compute"
    );
    assert_eq!(grouped_table(&contract), vec![1, 0, 0, 0]);
}

/// INBOUND: the interpreter must see the CURRENT value of each leaf. If the
/// grouped entry is never spread over the synthetic names, `self.table[i] += 1`
/// evaluates against an absent property and every bump computes from the
/// property's `initialValue`.
#[test]
fn inbound_repeated_bumps_of_one_slot_accumulate() {
    let (mut contract, mut provider, signer) = deploy_array_write();

    for n in 1..=3i64 {
        contract
            .call("bump", &[SdkValue::Int(0)], &mut provider, &signer, None)
            .unwrap_or_else(|e| panic!("call(bump, 0) #{} failed: {}", n, e));
        assert_eq!(
            state_tail_hex(&contract.get_utxo().unwrap().script),
            le_hex(&[n, 0, 0, 0]),
            "after {} bump(0) call(s)",
            n
        );
        assert_eq!(grouped_table(&contract), vec![n, 0, 0, 0]);
    }
}

/// INBOUND, the sharper probe and the one that costs money: a contract
/// reconnected with `from_utxo` carries the grouped entry ONLY. Without the
/// inbound bridge the interpreter falls back to each leaf's ANF `initialValue`,
/// and because the runtime-index write lowers to a per-leaf select it rewrites
/// ALL FOUR leaves — the call silently rewinds the array to its deploy-time
/// contents and commits that to the continuation output.
#[test]
fn inbound_reconnected_contract_commits_the_restored_state() {
    let (mut contract, mut provider, signer) = deploy_array_write();

    // Real on-chain history: table -> [0,2,0,0].
    for n in 1..=2 {
        contract
            .call("bump", &[SdkValue::Int(1)], &mut provider, &signer, None)
            .unwrap_or_else(|e| panic!("call(bump, 1) #{} failed: {}", n, e));
    }
    let on_chain = contract.get_utxo().expect("deployed").clone();
    assert_eq!(
        state_tail_hex(&on_chain.script),
        le_hex(&[0, 2, 0, 0]),
        "state section before reconnect"
    );

    // A fresh process that only ever sees the deployed script.
    let mut restored = RunarContract::from_utxo(load_artifact(), &on_chain);
    assert!(
        !restored.state().contains_key("table__1"),
        "from_utxo leaked a synthetic leaf; this test no longer probes the grouped-only restore path"
    );
    assert_eq!(grouped_table(&restored), vec![0, 2, 0, 0]);

    restored
        .call("bump", &[SdkValue::Int(1)], &mut provider, &signer, None)
        .expect("call(bump, 1) after reconnect should succeed");

    assert_eq!(
        state_tail_hex(&restored.get_utxo().unwrap().script),
        le_hex(&[0, 3, 0, 0]),
        "the interpreter did not see the restored leaves"
    );
    assert_eq!(grouped_table(&restored), vec![0, 3, 0, 0]);
}
