//! Issue #106 — `SdkValue::EmptySig` producer-side convention for OR-CHECKSIG
//! branched authorization.
//!
//! An OR-CHECKSIG method — `checkSig(sigA, pkA) || checkSig(sigB, pkB)` — runs
//! BOTH `OP_CHECKSIG` branches (Rúnar lowers `||` to the non-lazy `OP_BOOLOR`).
//! Only the matching branch supplies a real signature; the failing branch MUST
//! push an empty signature (OP_0) or BIP146 NULLFAIL rejects the whole spend.
//!
//! GREEN proof (interpreter-level):
//!   * `[Auto, EmptySig]` — the SDK signs only the Auto slot; the EmptySig slot
//!     stays OP_0 → the failing CHECKSIG returns false without aborting → the
//!     spend VALIDATES through the bsv-sdk `Spend` interpreter.
//!
//! RED baseline (wire-level):
//!   * `[Auto, Auto]` fills BOTH sig slots with Alice's signature, so the
//!     non-matching branch carries a NON-EMPTY, invalid signature — exactly the
//!     byte pattern BIP146 NULLFAIL rejects. `[Auto, EmptySig]` instead emits
//!     OP_0 (empty push) in that slot.
//!
//! Note on the interpreter: the Rust `bsv-sdk` (v0.1.72) `Spend` does NOT
//! implement SCRIPT_VERIFY_NULLFAIL — a non-empty invalid signature makes
//! CHECKSIG push `false` rather than abort — so it cannot itself REJECT the
//! `[Auto, Auto]` tx. The interpreter-level NULLFAIL rejection is proven on the
//! TypeScript side, where `@bsv/sdk`'s `Spend` enforces NULLFAIL (the rule the
//! issue cites at `Spend.ts:1326`). Here the Rust RED baseline is captured at
//! the wire level: the failing branch's push is non-empty under `[Auto, Auto]`
//! and empty (OP_0) under `[Auto, EmptySig]`.

use bsv::script::spend::{Spend, SpendParams};
use bsv::transaction::transaction::Transaction;
use bsv::transaction::transaction_input::TransactionInput;

use runar_lang::sdk::types::{Abi, AbiConstructor, AbiMethod, AbiParam, RunarArtifact};
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::{DeployOptions, LocalSigner, MockProvider, RunarContract, SdkValue, Signer, Utxo};

// Alice authorizes branch A; Bob's key is embedded but never signs (branch B).
const ALICE_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";
const BOB_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000007";
const CONTRACT_SATS: i64 = 50_000;

/// Hand-built OR-CHECKSIG locking script that mirrors what the Rúnar compiler
/// emits for `assert(checkSig(sigA, pkA) || checkSig(sigB, pkB))`:
///
///   OP_SWAP <pkA> OP_CHECKSIG OP_SWAP <pkB> OP_CHECKSIG OP_BOOLOR
///
/// Unlocking script pushes args in ABI order (sigA, then sigB), so the stack is
/// `[sigA, sigB]`. The two swaps line each branch's sig up under its pubkey for
/// `OP_CHECKSIG`, and `OP_BOOLOR` combines the two branch results.
fn or_checksig_script(pk_a_hex: &str, pk_b_hex: &str) -> String {
    // 7c = OP_SWAP, 21 = PUSH(33), ac = OP_CHECKSIG, 9b = OP_BOOLOR
    format!("7c21{}ac7c21{}ac9b", pk_a_hex, pk_b_hex)
}

fn or_checksig_artifact(pk_a_hex: &str, pk_b_hex: &str) -> RunarArtifact {
    RunarArtifact {
        version: "runar-v0.1.0".to_string(),
        contract_name: "OrChecksig".to_string(),
        parent_class: None,
        abi: Abi {
            constructor: AbiConstructor { params: vec![] },
            methods: vec![AbiMethod {
                name: "execute".to_string(),
                params: vec![
                    AbiParam { name: "sigA".to_string(), param_type: "Sig".to_string(), fixed_array: None },
                    AbiParam { name: "sigB".to_string(), param_type: "Sig".to_string(), fixed_array: None },
                ],
                is_public: true,
                is_terminal: None,
                uses_code_part: None,
                sig_hash_type: None,
            }],
        },
        script: or_checksig_script(pk_a_hex, pk_b_hex),
        asm: None,
        state_fields: None,
        constructor_slots: None,
        code_sep_index_slots: None,
        code_separator_index: None,
        code_separator_indices: None,
        anf: None,
    }
}

/// Deploy a fresh OR-CHECKSIG contract funded by Alice.
/// Returns (contract, provider, alice_signer, deploy_tx_hex).
fn deploy() -> (RunarContract, MockProvider, LocalSigner, String) {
    let alice = LocalSigner::new(ALICE_KEY).unwrap();
    let bob = LocalSigner::new(BOB_KEY).unwrap();
    let pk_a = alice.get_public_key().unwrap();
    let pk_b = bob.get_public_key().unwrap();

    let mut provider = MockProvider::testnet();
    let address = alice.get_address().unwrap();
    provider.add_utxo(&address, Utxo {
        txid: "cc".repeat(32),
        output_index: 0,
        satoshis: 200_000,
        script: build_p2pkh_script(&address),
    });

    let mut contract = RunarContract::new(or_checksig_artifact(&pk_a, &pk_b), Vec::<SdkValue>::new());
    contract
        .deploy(&mut provider, &alice, &DeployOptions {
            satoshis: CONTRACT_SATS,
            change_address: None,
            funding_signer: None,
        })
        .unwrap();
    let deploy_tx = provider.get_broadcasted_txs()[0].clone();
    (contract, provider, alice, deploy_tx)
}

/// Replay input 0 (the contract input) of `call_tx` through the bsv-sdk `Spend`
/// interpreter with the real spending-transaction context, so CHECKSIG +
/// NULLFAIL actually run. Returns Ok(true) only for a fully-valid spend.
fn validate_contract_spend(call_tx_hex: &str, deploy_tx_hex: &str) -> Result<bool, String> {
    let tx = Transaction::from_hex(call_tx_hex).map_err(|e| format!("call tx: {e:?}"))?;
    let deploy = Transaction::from_hex(deploy_tx_hex).map_err(|e| format!("deploy tx: {e:?}"))?;

    let input = tx.inputs[0].clone();
    let src_idx = input.source_output_index as usize;
    let source_output = deploy.outputs.get(src_idx).cloned().ok_or("missing source output")?;
    let source_txid = input.source_txid.clone().ok_or("missing source txid")?;
    let other_inputs: Vec<TransactionInput> = tx.inputs.iter().skip(1).cloned().collect();

    let params = SpendParams {
        locking_script: source_output.locking_script.clone(),
        unlocking_script: input.unlocking_script.clone().ok_or("missing unlocking script")?,
        source_txid,
        source_output_index: src_idx,
        source_satoshis: source_output.satoshis.unwrap_or(0),
        transaction_version: tx.version,
        transaction_lock_time: tx.lock_time,
        transaction_sequence: input.sequence,
        other_inputs,
        other_outputs: tx.outputs.clone(),
        input_index: 0,
    };
    let mut spend = Spend::new(params);
    spend.validate().map_err(|e| format!("{e:?}"))
}

/// Extract input 0's scriptSig (unlocking script) hex from a raw tx.
fn input0_script_sig(tx_hex: &str) -> String {
    let bytes: Vec<u8> = (0..tx_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&tx_hex[i..i + 2], 16).unwrap())
        .collect();
    let mut p = 4usize; // version
    // input count varint (single-byte for our small txs)
    assert!(bytes[p] < 0xfd, "unexpected large input count");
    p += 1;
    p += 32 + 4; // prev txid + index of input 0
    let slen = bytes[p] as usize; // scriptSig length varint (small)
    assert!(bytes[p] < 0xfd, "unexpected large scriptSig length");
    p += 1;
    bytes[p..p + slen].iter().map(|b| format!("{:02x}", b)).collect()
}

/// Parse the data elements pushed by a scriptSig. OP_0 yields an empty element.
fn parse_pushes(script_hex: &str) -> Vec<Vec<u8>> {
    let bytes: Vec<u8> = (0..script_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&script_hex[i..i + 2], 16).unwrap())
        .collect();
    let mut pushes = Vec::new();
    let mut p = 0;
    while p < bytes.len() {
        let op = bytes[p];
        p += 1;
        match op {
            0x00 => pushes.push(Vec::new()), // OP_0 → empty push
            0x01..=0x4b => {
                let n = op as usize;
                pushes.push(bytes[p..p + n].to_vec());
                p += n;
            }
            0x4c => {
                let n = bytes[p] as usize;
                p += 1;
                pushes.push(bytes[p..p + n].to_vec());
                p += n;
            }
            _ => pushes.push(vec![op]), // bare opcode (not expected here)
        }
    }
    pushes
}

#[test]
fn empty_sig_failing_branch_validates_through_spend() {
    let (mut contract, mut provider, alice, deploy_tx) = deploy();

    // Alice signs branch A (Auto); branch B is deliberately empty (EmptySig).
    contract
        .call(
            "execute",
            &[SdkValue::Auto, SdkValue::EmptySig],
            &mut provider,
            &alice,
            None,
        )
        .expect("call with [Auto, EmptySig] should build + broadcast");

    let call_tx = provider.get_broadcasted_txs()[1].clone();

    // GREEN: the built spend validates through the interpreter.
    let result = validate_contract_spend(&call_tx, &deploy_tx);
    assert_eq!(
        result,
        Ok(true),
        "[Auto, EmptySig] must VALIDATE (branch A signed, branch B empty); got {result:?}",
    );

    // Wire-level: branch A carries a real signature, branch B is OP_0 (empty).
    let pushes = parse_pushes(&input0_script_sig(&call_tx));
    assert_eq!(pushes.len(), 2, "two Sig slots expected");
    assert!(!pushes[0].is_empty(), "branch A must carry a real signature");
    assert!(
        pushes[1].is_empty(),
        "branch B (EmptySig) must be OP_0 / empty push — satisfies NULLFAIL; got {} bytes",
        pushes[1].len(),
    );
}

#[test]
fn double_auto_produces_nullfail_tripping_bytes() {
    let (mut contract, mut provider, alice, _deploy_tx) = deploy();

    // Both slots Auto → the SDK fills BOTH with Alice's signature.
    contract
        .call(
            "execute",
            &[SdkValue::Auto, SdkValue::Auto],
            &mut provider,
            &alice,
            None,
        )
        .expect("call with [Auto, Auto] should still build + broadcast");

    let call_tx = provider.get_broadcasted_txs()[1].clone();

    // RED baseline (wire level): the failing branch (B) carries a NON-EMPTY
    // signature — the exact byte pattern BIP146 NULLFAIL rejects on a compliant
    // node. It is identical to branch A's signature (same single signer).
    let pushes = parse_pushes(&input0_script_sig(&call_tx));
    assert_eq!(pushes.len(), 2, "two Sig slots expected");
    assert!(!pushes[0].is_empty(), "branch A must carry a real signature");
    assert!(
        !pushes[1].is_empty(),
        "branch B is non-empty under [Auto, Auto] — this is what trips NULLFAIL",
    );
    assert_eq!(
        pushes[0], pushes[1],
        "both slots get the same single-signer signature under [Auto, Auto]",
    );
}
