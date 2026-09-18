//! R-054: `checkMultiSig` must reject a degenerate threshold at COMPILE time.
//!
//! `checkMultiSig([], [pk])` lowers to
//!
//! ```text
//! OP_0 OP_0 <pk> OP_1 OP_CHECKMULTISIG
//! ```
//!
//! i.e. nSigs = 0. OP_CHECKMULTISIG with zero required signatures pops the
//! pubkeys, verifies nothing, and pushes TRUE — the deployed output is
//! ANYONE-CAN-SPEND while the source reads like an authorization check.
//! Confirmed byte-identically across all seven tiers before the guard landed:
//! every one emitted `0000007b51ae` for the same contract.
//!
//! The mirror image, more signatures than public keys, can never be satisfied
//! by any witness: the output is permanently UNSPENDABLE.
//!
//! The guard lives in the lowerer rather than the typechecker so it also covers
//! the `--ir` input path (which these tests drive directly), and it is a
//! compile-time refusal rather than extra emitted opcodes so it moves no bytes
//! for existing valid contracts.

use runar_compiler_rust::{compile_from_ir_str_with_options, CompileOptions};

fn fold_off() -> CompileOptions {
    CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    }
}

/// Build ANF IR shaped like
///
/// ```text
/// sigN = load_param(sN); pkM = load_param(kM)
/// sigs = array_literal([...]); pks = array_literal([...])
/// r = checkMultiSig(sigs, pks); assert(r)
/// ```
fn threshold_ir(n_sigs: usize, n_pks: usize) -> String {
    let params: Vec<String> = (0..n_sigs)
        .map(|i| format!(r#"{{ "name": "s{i}", "type": "Sig" }}"#))
        .chain((0..n_pks).map(|i| format!(r#"{{ "name": "k{i}", "type": "PubKey" }}"#)))
        .collect();

    let mut body: Vec<String> = Vec::new();
    for i in 0..n_sigs {
        body.push(format!(
            r#"{{ "name": "sig{i}", "value": {{ "kind": "load_param", "name": "s{i}" }} }}"#
        ));
    }
    for i in 0..n_pks {
        body.push(format!(
            r#"{{ "name": "pk{i}", "value": {{ "kind": "load_param", "name": "k{i}" }} }}"#
        ));
    }
    let sig_refs: Vec<String> = (0..n_sigs).map(|i| format!(r#""sig{i}""#)).collect();
    let pk_refs: Vec<String> = (0..n_pks).map(|i| format!(r#""pk{i}""#)).collect();
    body.push(format!(
        r#"{{ "name": "sigs", "value": {{ "kind": "array_literal", "elements": [{}] }} }}"#,
        sig_refs.join(", ")
    ));
    body.push(format!(
        r#"{{ "name": "pks", "value": {{ "kind": "array_literal", "elements": [{}] }} }}"#,
        pk_refs.join(", ")
    ));
    body.push(
        r#"{ "name": "r", "value": { "kind": "call", "func": "checkMultiSig", "args": ["sigs", "pks"] } }"#
            .to_string(),
    );
    body.push(r#"{ "name": "t", "value": { "kind": "assert", "value": "r" } }"#.to_string());

    format!(
        r#"{{
  "contractName": "CheckMultiSigThresholdProbe",
  "properties": [],
  "methods": [
    {{
      "name": "unlock",
      "params": [{}],
      "body": [{}],
      "isPublic": true
    }}
  ]
}}"#,
        params.join(", "),
        body.join(", ")
    )
}

#[test]
fn empty_signature_array_is_rejected() {
    let err = compile_from_ir_str_with_options(&threshold_ir(0, 1), &fold_off())
        .expect_err("checkMultiSig([], [pk]) compiled cleanly — that script is anyone-can-spend");
    assert!(
        err.contains("at least one signature"),
        "expected an 'at least one signature' diagnostic, got: {err}"
    );
}

#[test]
fn empty_pubkey_array_is_rejected() {
    let err = compile_from_ir_str_with_options(&threshold_ir(1, 0), &fold_off())
        .expect_err("checkMultiSig([sig], []) compiled cleanly");
    assert!(
        err.contains("at least one public key"),
        "expected an 'at least one public key' diagnostic, got: {err}"
    );
}

#[test]
fn more_sigs_than_pubkeys_is_rejected() {
    let err = compile_from_ir_str_with_options(&threshold_ir(2, 1), &fold_off())
        .expect_err("m > n compiled cleanly — that script is unspendable");
    assert!(
        err.contains("cannot exceed"),
        "expected a 'cannot exceed' diagnostic, got: {err}"
    );
}

// --- controls: the guard must not break any valid threshold -----------------

#[test]
fn valid_thresholds_still_compile() {
    for (n_sigs, n_pks) in [(1usize, 1usize), (2, 3), (3, 3)] {
        let artifact = compile_from_ir_str_with_options(&threshold_ir(n_sigs, n_pks), &fold_off())
            .unwrap_or_else(|e| panic!("{n_sigs}-of-{n_pks} must still compile: {e}"));
        assert!(
            artifact.asm.contains("OP_CHECKMULTISIG"),
            "{n_sigs}-of-{n_pks} must emit OP_CHECKMULTISIG; asm: {}",
            artifact.asm
        );
    }
}
