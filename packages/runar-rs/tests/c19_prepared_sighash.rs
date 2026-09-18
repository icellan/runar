//! Deep-review finding C19 (P1) — `PreparedCall.sighash` must be the true
//! BIP-143 digest `hash256(preimage)` = `sha256(sha256(preimage))`, NOT the
//! intermediate `sha256(preimage)`.
//!
//! `PreparedCall.sighash` is handed to an EXTERNAL signer — a BRC-100-style
//! `signHash(digest)` wallet or a hardware signer — that ECDSA-signs those 32
//! bytes DIRECTLY, with no further hashing. Storing the single-hashed value
//! makes such a wallet sign the wrong message, and the node's real OP_CHECKSIG
//! rejects the spend.
//!
//! The default `call()` path hides the bug: it never reads
//! `PreparedCall.sighash`. It re-derives the digest inside
//! `LocalSigner::sign` (`bip143_sighash` -> `sha256d` -> `sign_prehash`), which
//! is correct by construction. Only the documented multi-signer
//! `prepare_call()` / `finalize_call()` path is affected.
//!
//! Ported from the TS reference fix in `packages/runar-sdk/src/contract.ts`
//! (`computeBip143Sighash`).
//!
//! # Verification strategy (no ScriptVM replay)
//!
//! The Rust tier's `ScriptVm` wraps `bsv-sdk`'s `Spend`, which cannot validate
//! ANY Rúnar OP_PUSH_TX covenant — it hard-disables the `OP_2MUL` (0x8d) the
//! push-tx machinery emits and aborts with `DisabledOpcode("OP_2MUL")` (see
//! `g1_raw_outputs_spend.rs` for the full write-up). A stateful call is exactly
//! such a covenant, so a full-tx replay cannot distinguish pre-fix from
//! post-fix here.
//!
//! Instead this test performs the cryptographic check OP_CHECKSIG itself
//! performs: the signature an external `signHash` wallet produces over
//! `prepared.sighash` MUST verify, under the owner's public key, against
//! `hash256(preimage)` — the message the on-chain CHECKSIG validates. Pre-fix
//! the wallet signs `sha256(preimage)` and that verification fails.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo,
};

const SIGNER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

/// A stateful contract whose public method takes an external `Sig` — the
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

fn sha256_once(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// Deploy SigCounter (count = 5, owner = the signer's pubkey) and hand back a
/// fresh call-provider seeded with a spare coin.
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
    // The call spends the deploy's contract output. Teach the FRESH call
    // provider about that outpoint, otherwise its fail-closed broadcast gate
    // would have nothing to check and would (correctly) refuse the ack.
    let contract_utxo = contract.get_utxo().expect("deploy tracks a contract UTXO").clone();
    call_provider.add_contract_utxo(&contract_utxo.script.clone(), contract_utxo);

    (contract, call_provider, signer)
}

/// `PreparedCall.sighash` must be `hash256(preimage)`, never `sha256(preimage)`.
#[test]
fn prepared_call_sighash_is_bip143_hash256() {
    let (mut contract, mut provider, signer) = deploy();

    let prepared = contract
        .prepare_call("inc", &[SdkValue::Auto], &mut provider, &signer, None)
        .expect("prepare_call should succeed");

    assert!(
        !prepared.preimage.is_empty(),
        "a stateful call must carry a BIP-143 preimage"
    );

    let preimage = hex_to_bytes(&prepared.preimage);
    let want = bytes_to_hex(&sha256d(&preimage));
    let wrong_single = bytes_to_hex(&sha256_once(&preimage));

    assert_ne!(
        prepared.sighash, wrong_single,
        "PreparedCall.sighash is sha256(preimage) — an external signHash() wallet \
         would ECDSA-sign the WRONG digest (want hash256 = {want})"
    );
    assert_eq!(
        prepared.sighash, want,
        "PreparedCall.sighash must be hash256(preimage)"
    );
}

/// End-to-end multi-signer proof: an external `signHash` wallet ECDSA-signs
/// `prepared.sighash` DIRECTLY (no extra hashing), `finalize_call` assembles
/// the transaction, and the resulting signature must verify against the digest
/// the on-chain OP_CHECKSIG validates — `hash256(preimage)`.
#[test]
fn external_sign_hash_wallet_signature_verifies_on_chain_digest() {
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

    // --- the external wallet: signHash(digest) -> DER sig, NO extra hashing ---
    let digest = hex_to_bytes(&prepared.sighash);
    assert_eq!(
        digest.len(),
        32,
        "prepared.sighash must be a 32-byte digest, got {} bytes",
        digest.len()
    );
    let signing_key = SigningKey::from_slice(&hex_to_bytes(SIGNER_KEY)).unwrap();
    let (raw_sig, _): (Signature, _) = signing_key
        .sign_prehash(&digest)
        .expect("external wallet sign_prehash");
    let normalized = raw_sig.normalize_s().unwrap_or(raw_sig);
    let mut der = normalized.to_der().as_bytes().to_vec();
    der.push(0x41); // ALL | FORKID
    let sig_hex = bytes_to_hex(&der);
    // --- end external wallet ---

    // What OP_CHECKSIG actually verifies against on-chain.
    let on_chain_digest = sha256d(&hex_to_bytes(&prepared.preimage));
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&hex_to_bytes(&signer.get_public_key().unwrap())).unwrap();
    assert!(
        verifying_key
            .verify_prehash(&on_chain_digest, &normalized)
            .is_ok(),
        "the external wallet's signature over PreparedCall.sighash does NOT verify \
         against the on-chain BIP-143 digest hash256(preimage) — OP_CHECKSIG would \
         reject this spend"
    );

    let sig_idx = prepared.sig_indices[0];
    let mut signatures = std::collections::HashMap::new();
    signatures.insert(sig_idx, sig_hex.clone());
    contract
        .finalize_call(&prepared, &signatures, &mut provider)
        .expect("finalize_call should succeed");

    let txs = provider.get_broadcasted_txs();
    assert_eq!(txs.len(), 1, "expected the call broadcast");
    assert!(
        txs[0].contains(&sig_hex),
        "the externally-produced signature must appear in the broadcast transaction"
    );
}

/// Guards the trace risk: nothing internal consumes `PreparedCall.sighash`, so
/// the default `call()` path must keep working end-to-end after the C19 change.
#[test]
fn default_call_path_still_works() {
    let (mut contract, mut provider, signer) = deploy();

    contract
        .call("inc", &[SdkValue::Auto], &mut provider, &signer, None)
        .expect("default call() should succeed");

    match contract.state().get("count") {
        Some(SdkValue::Int(n)) => assert_eq!(*n, 6, "count should have incremented to 6"),
        other => panic!("unexpected count state: {other:?}"),
    }
    assert_eq!(
        provider.get_broadcasted_txs().len(),
        1,
        "the call should have broadcast exactly one transaction"
    );
}
