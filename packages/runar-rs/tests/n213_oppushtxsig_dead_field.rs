//! N-213 — the Rust half of "remove the dead `PreparedCall.opPushTxSig`
//! field (and its wasted ECDSA sign per stateful call) from
//! Go/Rust/Python/Ruby/Zig SDKs, as F-369 did for TS".
//!
//! Since BUG-100 the unlocking script carries no spender-supplied OP_PUSH_TX
//! signature: `build_stateful_prefix`'s first parameter is accepted for
//! call-site compatibility but ignored (see its `let _ = op_sig_hex;`
//! discard). `op_push_tx_sig` was documented public surface on `PreparedCall`
//! that backed nothing a caller could use.
//!
//! `PreparedCall` derives only `Debug`/`Clone` (no `Serialize`), so field
//! absence is checked via the `Debug` representation: `#[derive(Debug)]`
//! prints each field's name, so `"op_push_tx_sig"` appears in `{:?}` output
//! pre-fix and disappears post-fix — the same wire-shape check the Go sibling
//! test makes via JSON, and the TS reference test makes via `'opPushTxSig' in
//! prepared`.
//!
//! This test does not prove anything about the other four SDKs in scope for
//! N-213 (Go/Python/Ruby/Zig — each gets its own language-appropriate
//! field-absence test) or a real on-chain broadcast. The Rust `ScriptVm`
//! cannot replay a stateful OP_PUSH_TX covenant at all (see
//! `c19_prepared_sighash.rs`'s module doc), so — like that test — this one
//! proves the multi-signer flow still succeeds (prepare_call -> external
//! signHash -> finalize_call -> broadcast), not a script-interpreter replay.

use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};

use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

/// Same shape as `c19_prepared_sighash.rs`'s `SigCounter` — a stateful
/// contract whose public method takes an external `Sig`, i.e. the
/// multi-signer / hardware-wallet shape `prepare_call()` exists to serve.
const SRC: &str = r#"
    class SigCounter extends StatefulSmartContract {
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
    let compiler_art = runar_compiler_rust::compile_from_source_str(SRC, Some("SigCounter.runar.ts"))
        .expect("SigCounter source should compile");
    let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
    serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn deploy() -> (RunarContract, MockProvider, LocalSigner) {
    let signer = LocalSigner::new(SIGNER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pubkey = signer.get_public_key().unwrap();

    let mut deploy_provider = MockProvider::testnet();
    deploy_provider.add_utxo(
        &address,
        Utxo {
            txid: "aa".repeat(32),
            output_index: 0,
            satoshis: 500_000,
            script: build_p2pkh_script(&address),
        },
    );

    let mut contract = RunarContract::new(
        compile_sig_counter(),
        vec![SdkValue::Int(5), SdkValue::Bytes(pubkey)],
    );
    contract
        .deploy(
            &mut deploy_provider,
            &signer,
            &DeployOptions {
                satoshis: 50_000,
                change_address: None,
                funding_signer: None,
                acknowledge_unsound: vec![],
            },
        )
        .expect("deploy should succeed");

    let mut call_provider = MockProvider::testnet();
    call_provider.add_utxo(
        &address,
        Utxo {
            txid: "bb".repeat(32),
            output_index: 1,
            satoshis: 500_000,
            script: build_p2pkh_script(&address),
        },
    );
    let contract_utxo = contract.get_utxo().expect("deploy tracks a contract UTXO").clone();
    call_provider.add_contract_utxo(&contract_utxo.script.clone(), contract_utxo);

    (contract, call_provider, signer)
}

#[test]
fn prepared_call_has_no_op_push_tx_sig_field() {
    let (mut contract, mut provider, signer) = deploy();

    let prepared = contract
        .prepare_call("inc", &[SdkValue::Auto], &mut provider, &signer, None)
        .expect("prepare_call should succeed");

    let debug_repr = format!("{:?}", prepared);
    assert!(
        !debug_repr.contains("op_push_tx_sig"),
        "PreparedCall's Debug output still carries the dead op_push_tx_sig field: {debug_repr}"
    );

    // End-to-end: the external signHash() wallet flow (prepare_call ->
    // external signHash(sighash) -> finalize_call -> broadcast) must still
    // work after removing the field — nothing in that path ever needed it.
    assert_eq!(
        prepared.sig_indices.len(),
        1,
        "expected exactly one external Sig slot, got {:?}",
        prepared.sig_indices
    );
    let digest = hex_to_bytes(&prepared.sighash);
    assert_eq!(digest.len(), 32, "prepared.sighash must be a 32-byte digest");

    let signing_key = SigningKey::from_slice(&hex_to_bytes(SIGNER_KEY)).unwrap();
    let (raw_sig, _): (Signature, _) = signing_key
        .sign_prehash(&digest)
        .expect("external wallet sign_prehash");
    let normalized = raw_sig.normalize_s().unwrap_or(raw_sig);
    let mut der = normalized.to_der().as_bytes().to_vec();
    der.push(0x41); // ALL | FORKID
    let sig_hex = bytes_to_hex(&der);

    let sig_idx = prepared.sig_indices[0];
    let mut signatures = std::collections::HashMap::new();
    signatures.insert(sig_idx, sig_hex.clone());
    contract
        .finalize_call(&prepared, &signatures, &mut provider)
        .expect("finalize_call should still succeed after removing op_push_tx_sig");

    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1, "expected the call broadcast");
    assert!(
        txs[0].contains(&sig_hex),
        "the externally-produced signature must appear in the broadcast transaction"
    );
}
