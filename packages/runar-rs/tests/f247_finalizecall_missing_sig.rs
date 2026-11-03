//! F-247 (CL-BUG-136, MEDIUM/P2): `finalize_call` broadcasts a 72-byte
//! all-zero placeholder when a declared `sig_indices` slot is left unfilled.
//!
//! `prepare_call` stubs every auto-signed `Sig` param with a 72-zero-byte
//! placeholder and records its arg index in `sig_indices`. `finalize_call`
//! only overwrote `resolved_args[idx]` for the indices actually present in
//! the caller-supplied `signatures` map — nothing checked that every entry
//! in `prepared.sig_indices` was covered before the primary unlocking
//! script was assembled and handed to `provider.broadcast()`. Ported from
//! the TS fix in `packages/runar-sdk/src/contract.ts`.
//!
//! This test deliberately avoids `MockProvider::always_ack` (which would
//! need an `always_ack_allowlist.json` entry and the default validating
//! `MockProvider` would mask the bug by rejecting the placeholder-signed
//! broadcast for the WRONG reason — script invalidity caught AT broadcast
//! time — rather than showing whether `finalize_call` refuses BEFORE
//! calling `provider.broadcast()` at all). Instead it hand-rolls a minimal
//! `Provider` whose `broadcast()` acks anything, like a real network node
//! that does not pre-validate scripts.

use std::collections::HashMap;

use bsv::transaction::Transaction as BsvTransaction;

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, Provider, RunarContract, SdkValue, Signer,
    TransactionData, Utxo,
};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000009";

const SRC: &str = r#"
    class F247SigCounter extends StatefulSmartContract {
      count: bigint;
      readonly owner: PubKey;
      constructor(count: bigint, owner: PubKey) {
        super(count, owner);
        this.count = count;
        this.owner = owner;
      }
      public inc(sig: Sig) {
        assert(checkSig(sig, this.owner));
        this.count = this.count + 1n;
      }
    }
"#;

fn compile_sig_counter() -> RunarArtifact {
    let compiler_art =
        runar_compiler_rust::compile_from_source_str(SRC, Some("F247SigCounter.runar.ts"))
            .expect("F247SigCounter source should compile");
    let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
    serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
}

/// Delegates every read to an underlying `MockProvider` but `broadcast()`
/// acks unconditionally — no script validation — mirroring a real network
/// provider. Not a `MockProvider::always_ack` usage: a plain hand-rolled
/// `Provider`.
struct AckAnythingProvider {
    inner: MockProvider,
    broadcasted_txs: Vec<String>,
}

impl Provider for AckAnythingProvider {
    fn get_transaction(&self, txid: &str) -> Result<TransactionData, String> {
        self.inner.get_transaction(txid)
    }
    fn broadcast(&mut self, tx: &BsvTransaction) -> Result<String, String> {
        let raw_tx = tx.to_hex().map_err(|e| format!("to_hex failed: {}", e))?;
        self.broadcasted_txs.push(raw_tx.clone());
        // Deterministic fake txid derived from the raw tx — this test never
        // inspects the txid value, only whether broadcast() was called.
        Ok(format!("{:064x}", self.broadcasted_txs.len()))
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

fn deploy() -> (RunarContract, AckAnythingProvider, LocalSigner) {
    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pubkey = signer.get_public_key().unwrap();

    let mut mock = MockProvider::testnet();
    mock.add_utxo(
        &address,
        Utxo {
            txid: "dd".repeat(32),
            output_index: 0,
            satoshis: 500_000,
            script: build_p2pkh_script(&address),
        },
    );
    let mut provider = AckAnythingProvider { inner: mock, broadcasted_txs: Vec::new() };

    let mut contract = RunarContract::new(
        compile_sig_counter(),
        vec![SdkValue::Int(0), SdkValue::Bytes(pubkey)],
    );
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

/// What this test proves: calling `finalize_call` with an empty `signatures`
/// map for a method with one declared `sig_indices` entry returns an error
/// — before `provider.broadcast()` is ever reached (the broadcast count does
/// not grow).
///
/// What this test does NOT prove: multi-signer (2+ `sig_indices`) coverage
/// with SOME but not all slots filled — covered logically by the same
/// missing-index scan in the fix, but not exercised by a dedicated fixture
/// here.
#[test]
fn finalize_call_with_missing_sig_index_refuses_instead_of_broadcasting() {
    let (mut contract, mut provider, signer) = deploy();

    let prepared = contract
        .prepare_call("inc", &[SdkValue::Auto], &mut provider, &signer, None)
        .expect("prepare_call should succeed");
    assert_eq!(
        prepared.sig_indices.len(),
        1,
        "expected exactly one external Sig slot, got {:?}",
        prepared.sig_indices
    );

    let broadcast_count_before = provider.broadcasted_txs.len();

    // Caller forgets the one declared signature slot entirely.
    let signatures: HashMap<usize, String> = HashMap::new();
    let result = contract.finalize_call(&prepared, &signatures, &mut provider);

    assert!(
        result.is_err(),
        "finalize_call succeeded with a missing signature for a declared sig_indices slot; \
         want a refusal naming the missing index before broadcasting"
    );
    let msg = result.unwrap_err();
    assert!(
        msg.to_lowercase().contains("sig") || msg.to_lowercase().contains("signature"),
        "error does not name the missing signature slot: {}",
        msg
    );

    assert_eq!(
        provider.broadcasted_txs.len(),
        broadcast_count_before,
        "provider.broadcast was called despite the missing signature"
    );
}
