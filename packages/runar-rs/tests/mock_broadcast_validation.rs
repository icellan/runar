//! Testing-gap remediation Phase A5 (Rust tier): `MockProvider::broadcast` is
//! fail-CLOSED by default. It replays every input whose outpoint the provider
//! knows through `bsv-sdk`'s `Spend` with full transaction context, enforces
//! value conservation, and refuses to hand back a fake txid for a transaction
//! a real node would reject.
//!
//! The TypeScript reference (`packages/runar-sdk/src/providers/mock.ts`) has a
//! fail-OPEN hole this port deliberately closes: a transaction none of whose
//! inputs are known validated NOTHING and was accepted. Here that is an error,
//! so the gate can never pass vacuously.
//!
//! Divergence recorded honestly rather than papered over: Rúnar targets
//! **Chronicle**, the post-Genesis BSV profile that re-enables `OP_2MUL`
//! (0x8d), and every OP_PUSH_TX covenant emits that opcode. `bsv-sdk`
//! implements the pre-Chronicle policy and hard-disables it, aborting with
//! `disabled opcode: OP_2MUL`. Such an input is counted as UNVALIDATABLE, never
//! as validated — so it can never satisfy the non-vacuity requirement on its
//! own. See `last_validation_report()`.
//!
//! The other bound this file used to record — `bsv-sdk` mis-ordering
//! `hashPrevouts` for `input_index > 0` — is **fixed as of 0.2.89**, which
//! `Cargo.toml` now requires; every known input is validated at every index.

use std::path::Path;

use bsv::script::{LockingScript, UnlockingScript};
use bsv::transaction::{
    Transaction as BsvTx, TransactionInput as BsvTxIn, TransactionOutput as BsvTxOut,
};
use runar_lang::sdk::script_utils::build_p2pkh_script;
use runar_lang::sdk::types::RunarArtifact;
use runar_lang::sdk::{
    DeployOptions, LocalSigner, MockProvider, Provider, RunarContract, SdkValue, Signer, Utxo,
};

const ANYONE_CAN_SPEND: &str = "51"; // OP_TRUE
const DEPLOYER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000003";

/// Minimal stateful contract — compiles to an OP_PUSH_TX continuation covenant,
/// which is the script class `bsv-sdk` cannot run (see the OP_2MUL pins).
const STATEFUL_COUNTER_SRC: &str = r#"
    class SatCounter extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      public inc() {
        this.count = this.count + 1n;
        this.addOutput(1000n, this.count);
      }
    }
"#;

/// One-input, one-output transaction spending `prev_txid:0`.
fn one_input_tx(prev_txid: &str, unlocking_hex: &str, out_sats: u64) -> BsvTx {
    let mut tx = BsvTx::new();
    tx.add_input(BsvTxIn {
        source_txid: Some(prev_txid.to_string()),
        source_output_index: 0,
        unlocking_script: Some(UnlockingScript::from_hex(unlocking_hex).unwrap()),
        sequence: 0xffff_ffff,
        source_transaction: None,
    });
    tx.add_output(BsvTxOut {
        satoshis: Some(out_sats),
        locking_script: LockingScript::from_hex(ANYONE_CAN_SPEND).unwrap(),
        change: false,
    });
    tx
}

fn seed(provider: &mut MockProvider, txid: &str, satoshis: i64, script: &str) {
    provider.add_utxo(
        "addr",
        Utxo {
            txid: txid.to_string(),
            output_index: 0,
            satoshis,
            script: script.to_string(),
        },
    );
}

// --- rejection: script-invalid spend ----------------------------------------

#[test]
fn broadcast_rejects_script_invalid_spend() {
    let mut p = MockProvider::testnet();
    // "00" is OP_0: leaves a falsey top of stack, so the spend must fail.
    seed(&mut p, &"11".repeat(32), 10_000, "00");
    let tx = one_input_tx(&"11".repeat(32), "", 1_000);

    let err = p
        .broadcast(&tx)
        .expect_err("MockProvider accepted a script-INVALID transaction; validation is fail-open");
    assert!(err.contains("input 0"), "error should name the failing input: {}", err);
}

// --- rejection: underfunded --------------------------------------------------

#[test]
fn broadcast_rejects_underfunded_tx() {
    let mut p = MockProvider::testnet();
    seed(&mut p, &"22".repeat(32), 1_000, ANYONE_CAN_SPEND);
    let tx = one_input_tx(&"22".repeat(32), "", 5_000);

    let err = p
        .broadcast(&tx)
        .expect_err("MockProvider accepted an UNDERFUNDED transaction (outputs 5000 > inputs 1000)");
    assert!(err.contains("underfunded"), "expected an underfunded error, got: {}", err);
}

// --- rejection: vacuous validation (zero inputs actually executed) -----------

#[test]
fn broadcast_rejects_vacuous_validation() {
    let mut p = MockProvider::testnet();
    // Nothing seeded: the provider knows no outpoints, so it can execute
    // nothing. A gate that validates nothing is worse than no gate.
    let tx = one_input_tx(&"33".repeat(32), "", 1_000);

    let err = p.broadcast(&tx).expect_err(
        "MockProvider accepted a transaction whose inputs are ALL unknown — \
         validation ran on zero inputs and passed vacuously",
    );
    assert!(
        err.contains("NOTHING was checked") && err.contains("0 of 1 inputs executed"),
        "expected a non-vacuity error naming the validated/total counts, got: {}",
        err
    );
}

// --- pins on the upstream bsv-sdk behaviour this tier's gate depends on -----

/// `bsv-sdk` 0.1.72 built `hashPrevouts` as "current input's outpoint first,
/// then other_inputs" — transaction input order only for `input_index == 0` —
/// so a genuine BIP-143 signature on input 1 evaluated to FALSE. That is why
/// `validate_broadcast_tx` used to refuse to draw any conclusion from inputs at
/// index > 0.
///
/// **Fixed as of 0.2.89**, which `Cargo.toml` now requires. This pin is the
/// load-bearing evidence for having deleted that carve-out: it goes RED if a
/// future bsv-sdk regresses multi-input sighashing, which would mean
/// `validate_broadcast_tx` is once again drawing conclusions it may not draw.
#[test]
fn pin_bsv_sdk_sighashes_every_input_index_correctly() {
    use bsv::script::spend::{Spend, SpendParams};

    let signer = LocalSigner::new(DEPLOYER_KEY).unwrap();
    let pubkey = signer.get_public_key().unwrap();
    let script = build_p2pkh_script(&pubkey);

    let mut tx = BsvTx::new();
    for t in ["aa", "bb"] {
        tx.add_input(BsvTxIn {
            source_txid: Some(t.repeat(32)),
            source_output_index: 0,
            unlocking_script: None,
            sequence: 0xffff_ffff,
            source_transaction: None,
        });
    }
    tx.add_output(BsvTxOut {
        satoshis: Some(1_000),
        locking_script: LockingScript::from_hex(ANYONE_CAN_SPEND).unwrap(),
        change: false,
    });
    let tx_hex = tx.to_hex().unwrap();
    for i in 0..2 {
        let sig = signer.sign(&tx_hex, i, &script, 10_000, None).unwrap();
        let unlock = format!("{:02x}{}{:02x}{}", sig.len() / 2, sig, pubkey.len() / 2, pubkey);
        tx.inputs[i].unlocking_script = Some(UnlockingScript::from_hex(&unlock).unwrap());
    }

    let verdict = |i: usize| -> bool {
        let others: Vec<_> = tx
            .inputs
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, v)| v.clone())
            .collect();
        Spend::new(SpendParams {
            locking_script: LockingScript::from_hex(&script).unwrap(),
            unlocking_script: tx.inputs[i].unlocking_script.clone().unwrap(),
            source_txid: tx.inputs[i].source_txid.clone().unwrap(),
            source_output_index: 0,
            source_satoshis: 10_000,
            transaction_version: tx.version,
            transaction_lock_time: tx.lock_time,
            transaction_sequence: tx.inputs[i].sequence,
            other_inputs: others,
            other_outputs: tx.outputs.clone(),
            input_index: i,
        })
        .validate()
        .unwrap_or(false)
    };

    assert!(verdict(0), "input 0 must validate — if this fails, bsv-sdk's BIP-143 broke entirely");
    assert!(
        verdict(1),
        "bsv-sdk has REGRESSED BIP-143 sighashing for input_index > 0. \
         src/sdk/provider.rs::validate_broadcast_tx executes every known input on the \
         strength of this pin; restore an index carve-out there before trusting it again."
    );
}

/// Rúnar targets **Chronicle**, the post-Genesis BSV profile that re-enables
/// `OP_2MUL` (0x8d) — `06-emit.ts` maps it as such, and the OP_PUSH_TX low-S
/// normalisation (`oppushtx-codegen.ts`) emits it, so it appears as a real
/// opcode in EVERY stateful contract's covenant. `bsv-sdk` implements the
/// pre-Chronicle policy and hard-disables `OP_2MUL` with no config escape.
///
/// This is NOT a parser desync (an earlier write-up said so): a correct script
/// walk lands on 0x8d at a genuine opcode boundary. It is an opcode-profile
/// mismatch, which is why `validate_broadcast_tx` tolerates exactly one error
/// class and buckets those inputs as `unvalidatable`.
///
/// Minimal pin: a bare `OP_2MUL` script. Goes RED the day bsv-sdk adopts the
/// Chronicle opcode set — at which point the tolerated-error class in
/// `validate_broadcast_tx` should be deleted.
#[test]
fn pin_bsv_sdk_rejects_op2mul_disabled_by_pre_chronicle_policy() {
    use bsv::script::spend::{Spend, SpendParams};

    // <1> OP_2MUL  — on Chronicle this leaves 2 on the stack and succeeds.
    let err = Spend::new(SpendParams {
        locking_script: LockingScript::from_hex("8d").unwrap(),
        unlocking_script: UnlockingScript::from_hex("51").unwrap(),
        source_txid: "ee".repeat(32),
        source_output_index: 0,
        source_satoshis: 10_000,
        transaction_version: 1,
        transaction_lock_time: 0,
        transaction_sequence: 0xffff_ffff,
        other_inputs: vec![],
        other_outputs: vec![],
        input_index: 0,
    })
    .validate()
    .err()
    .map(|e| e.to_string());

    assert_eq!(
        err.as_deref(),
        Some("disabled opcode: OP_2MUL"),
        "bsv-sdk now runs OP_2MUL (Chronicle opcode set adopted). Delete the \
         `disabled opcode` tolerated-error class in \
         src/sdk/provider.rs::validate_broadcast_tx so Rúnar covenant inputs are \
         script-validated instead of bucketed as `unvalidatable`."
    );
}

/// End-to-end companion to the pin above: a REAL compiled Rúnar stateful
/// covenant, spent through the SDK's own call path, still cannot be executed by
/// `bsv-sdk` — so the primary fund path of a stateful contract is bucketed
/// `unvalidatable`, never `validated`. This is the finding the bare-opcode pin
/// abstracts, kept alongside it so the consequence is stated in Rúnar's own
/// terms and goes RED at the same moment.
#[test]
fn pin_runar_stateful_covenant_input_is_unvalidatable_by_bsv_sdk() {
    let signer = LocalSigner::new(DEPLOYER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let funding = build_p2pkh_script(&signer.get_public_key().unwrap());

    let mut deploy_provider = MockProvider::testnet();
    deploy_provider.add_utxo(
        &address,
        Utxo {
            txid: "a1".repeat(32),
            output_index: 0,
            satoshis: 500_000,
            script: funding.clone(),
        },
    );

    let artifact: RunarArtifact = {
        let compiler_art = runar_compiler_rust::compile_from_source_str(
            STATEFUL_COUNTER_SRC,
            Some("SatCounter.runar.ts"),
        )
        .expect("SatCounter source should compile");
        let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
        serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
    };

    let mut contract = RunarContract::new(artifact, vec![SdkValue::Int(5)]);
    contract
        .deploy(
            &mut deploy_provider,
            &signer,
            &DeployOptions { satoshis: 1, change_address: None, funding_signer: None, acknowledge_unsound: vec![] },
        )
        .expect("deploy should succeed");

    let mut call_provider = MockProvider::testnet();
    call_provider.add_utxo(
        &address,
        Utxo {
            txid: "b1".repeat(32),
            output_index: 1,
            satoshis: 500_000,
            script: funding,
        },
    );
    let contract_utxo = contract.get_utxo().expect("deploy tracks a contract UTXO").clone();
    call_provider.add_contract_utxo(&contract_utxo.script.clone(), contract_utxo);

    contract
        .call("inc", &[], &mut call_provider, &signer, None)
        .expect("call(inc) should build + broadcast");

    let r = call_provider.last_validation_report();
    assert_eq!(r.total, 2, "the call spends the covenant plus one funding coin");
    assert_eq!(
        r.unvalidatable, 1,
        "the covenant input must be bucketed as unvalidatable — if this is now 0, bsv-sdk \
         can run Rúnar covenants and the tolerated-error class in validate_broadcast_tx \
         should be deleted; report was {:?}",
        r
    );
    assert_eq!(
        r.validated, 1,
        "the funding input must still really execute (non-vacuity witness); report was {:?}",
        r
    );
}

/// A validating provider must never report an input it could not execute as
/// validated. This pins the bucket accounting itself: two known, spendable
/// inputs BOTH execute (index > 0 included, since bsv-sdk >= 0.2.89 sighashes
/// it correctly), while an input whose outpoint is unknown lands in `unknown`.
#[test]
fn report_buckets_never_count_an_unexecuted_input_as_validated() {
    let mut p = MockProvider::testnet();
    seed(&mut p, &"66".repeat(32), 10_000, ANYONE_CAN_SPEND);
    let mut tx = one_input_tx(&"66".repeat(32), "", 1_000);
    // Second input at index 1 — known and spendable, so it must EXECUTE now.
    p.add_utxo(
        "addr",
        Utxo {
            txid: "77".repeat(32),
            output_index: 0,
            satoshis: 10_000,
            script: ANYONE_CAN_SPEND.to_string(),
        },
    );
    tx.add_input(BsvTxIn {
        source_txid: Some("77".repeat(32)),
        source_output_index: 0,
        unlocking_script: Some(UnlockingScript::from_hex("").unwrap()),
        sequence: 0xffff_ffff,
        source_transaction: None,
    });
    // Third input at index 2 — outpoint this provider has never heard of.
    tx.add_input(BsvTxIn {
        source_txid: Some("88".repeat(32)),
        source_output_index: 0,
        unlocking_script: Some(UnlockingScript::from_hex("").unwrap()),
        sequence: 0xffff_ffff,
        source_transaction: None,
    });

    p.broadcast(&tx).expect("a 3-input tx whose two known inputs both pass is acceptable");
    let r = p.last_validation_report();
    assert_eq!(r.total, 3);
    assert_eq!(r.validated, 2, "BOTH known inputs must really execute, index 1 included");
    assert_eq!(r.unknown, 1, "the unknown outpoint must be reported as NOT executed");
    assert_eq!(r.unvalidatable, 0);
    assert!(
        !r.value_conserved,
        "one outpoint is unknown, so value conservation must NOT claim to have run"
    );
}

// --- rejection: unsigned transaction ----------------------------------------

#[test]
fn broadcast_rejects_input_without_unlocking_script() {
    let mut p = MockProvider::testnet();
    seed(&mut p, &"55".repeat(32), 10_000, ANYONE_CAN_SPEND);
    let mut tx = one_input_tx(&"55".repeat(32), "", 1_000);
    tx.inputs[0].unlocking_script = None;

    let err = p.broadcast(&tx).expect_err("an unsigned input must not be accepted");
    assert!(err.contains("unsigned"), "got: {}", err);
}

// --- acceptance: a valid spend of a known outpoint --------------------------

#[test]
fn broadcast_accepts_valid_spend_and_reports_non_vacuity() {
    let mut p = MockProvider::testnet();
    seed(&mut p, &"44".repeat(32), 10_000, ANYONE_CAN_SPEND);
    let tx = one_input_tx(&"44".repeat(32), "", 9_000);

    let txid = p.broadcast(&tx).expect("MockProvider rejected a VALID spend");
    assert_eq!(txid.len(), 64);
    assert_eq!(
        p.last_validated_input_count(),
        1,
        "the gate must report the input it actually executed (non-vacuity witness)"
    );
    assert_eq!(p.last_validation_report().unvalidatable, 0);
}

// --- acceptance: a real compiled contract's deploy ---------------------------

fn compile_counter() -> RunarArtifact {
    let src_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/rust/add-raw-output/RawOutputTest.runar.rs");
    let compiler_art = runar_compiler_rust::compile_from_source(&src_path)
        .expect("RawOutputTest.runar.rs should compile");
    let json = serde_json::to_string(&compiler_art).expect("serialize compiler artifact");
    serde_json::from_str(&json).expect("deserialize into SDK RunarArtifact")
}

#[test]
fn broadcast_accepts_real_deploy_with_a_spendable_funding_coin() {
    let signer = LocalSigner::new(DEPLOYER_KEY).unwrap();
    let address = signer.get_address().unwrap();
    let pubkey = signer.get_public_key().unwrap();
    let mut provider = MockProvider::testnet();
    // A REAL P2PKH funding script for this signer. The old fixture
    // ("76a914" + "00"*20 + "88ac") is not spendable by ANY key, so the deploy
    // input it produced would be rejected by a node — the pre-Phase-A5
    // always-ack MockProvider hid that.
    provider.add_utxo(
        &address,
        Utxo {
            txid: "cc".repeat(32),
            output_index: 0,
            satoshis: 500_000,
            script: build_p2pkh_script(&pubkey),
        },
    );

    let mut contract = RunarContract::new(compile_counter(), vec![SdkValue::Int(0)]);
    contract
        .deploy(
            &mut provider,
            &signer,
            &DeployOptions { satoshis: 50_000, change_address: None, funding_signer: None, acknowledge_unsound: vec![] },
        )
        .expect("deploy REJECTED by the validating MockProvider");

    assert_eq!(provider.get_broadcasted_txs().len(), 1);
    assert!(
        provider.last_validated_input_count() >= 1,
        "the deploy's P2PKH funding input must have really executed, got report {:?}",
        provider.last_validation_report()
    );
}

// --- the governed opt-out ----------------------------------------------------

#[test]
fn always_ack_provider_skips_validation() {
    let mut p = MockProvider::always_ack("testnet");
    let tx = one_input_tx(&"33".repeat(32), "", 1_000);
    p.broadcast(&tx).expect("always-ack provider must not validate");
}

#[test]
fn disable_and_re_enable_broadcast_validation() {
    let mut p = MockProvider::testnet();
    let tx = one_input_tx(&"33".repeat(32), "", 1_000);

    assert!(p.broadcast(&tx).is_err(), "default provider must validate");
    p.disable_broadcast_validation();
    assert!(p.broadcast(&tx).is_ok(), "after disable_broadcast_validation the provider must ack");
    p.enable_broadcast_validation(true);
    assert!(p.broadcast(&tx).is_err(), "after enable_broadcast_validation(true) it must validate again");
}
