//! The state-continuation WRITER must push-data-frame `Sig` and
//! `SigHashPreimage`, exactly like `ByteString` — the other half of R-015.
//!
//! `bc6cf19a` (R-015 / CL-BUG-138) fixed the READ side in this tier:
//! `compute_uses_code_part` now classifies `Sig` / `SigHashPreimage` with
//! `is_variable_length_state_type`. Its own commit message recorded the half it
//! did NOT fix, present in all seven tiers:
//!
//! > the write side is still wrong — `lower_add_output` push-data-encodes only
//! > `ByteString`, so a MUTATING method on a `Sig`-state contract emits a
//! > continuation the next spend cannot decode.
//!
//! That is the defect this file locks. Both serializers in `codegen/stack.rs`
//! (`:2999` in the compute-state-bytes path and `:3331` in `lower_add_output`)
//! tested `prop.prop_type == "ByteString"` before calling
//! `emit_push_data_encode`, while the reader — `lower_deserialize_state` — and
//! the SDK's deploy-time `encode_state_value` both push-data-frame every type
//! that is not fixed-size. So:
//!
//!   deploy  — SDK writes    <len> || DER      → correct, spendable
//!   spend 1 — script writes          DER      → continuation has NO length byte
//!   spend 2 — script reads DER[0] as a length → 0x30 = "a 48-byte push"
//!
//! The deploy succeeds, the first spend succeeds, and the UTXO that first spend
//! creates is unspendable. Fund loss, and invisible to any test that only
//! round-trips the compiler against itself.
//!
//! The lock: a mutating method on a `Sig` / `SigHashPreimage` field must
//! compile BYTE-IDENTICALLY to the same contract with a `ByteString` field —
//! the path that was already correct. `RabinSig` (a bigint alias stored as a
//! bare 8-byte NUM2BIN word) and `PubKey` (33 raw bytes) are the negative
//! controls and must stay DIFFERENT.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

const WRITE_FILE: &str = "VarLenStateWrite.runar.ts";

/// Mutating method — drives the state-continuation WRITE path.
fn write_src(prop_type: &str) -> String {
    format!(
        "import {{ StatefulSmartContract }} from 'runar-lang';\n\
         class VarLenStateWrite extends StatefulSmartContract {{\n\
         \x20 tag: {t};\n\
         \x20 constructor(tag: {t}) {{ super(tag); this.tag = tag; }}\n\
         \x20 public update(next: {t}): void {{ this.tag = next; }}\n\
         }}",
        t = prop_type
    )
}

fn script_hex(src: &str, file: &str) -> String {
    let opts = CompileOptions {
        disable_constant_folding: true,
        ..CompileOptions::default()
    };
    let result = compile_from_source_str_with_result(src, Some(file), &opts);
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error),
        "compile errors for {}: {:?}",
        file,
        result.diagnostics
    );
    result.script_hex.expect("no script hex")
}

fn control_hex() -> String {
    script_hex(&write_src("ByteString"), WRITE_FILE)
}

#[test]
fn sig_state_continuation_frames_like_bytestring() {
    let control = control_hex();
    let got = script_hex(&write_src("Sig"), WRITE_FILE);
    assert_eq!(
        got.len(),
        control.len(),
        "a mutable Sig field does not push-data-frame its continuation state \
         (len {} vs ByteString's {})",
        got.len(),
        control.len()
    );
    assert_eq!(
        got, control,
        "a mutable Sig field does not frame its continuation like ByteString"
    );
}

#[test]
fn sighash_preimage_state_continuation_frames_like_bytestring() {
    let control = control_hex();
    let got = script_hex(&write_src("SigHashPreimage"), WRITE_FILE);
    assert_eq!(
        got.len(),
        control.len(),
        "a mutable SigHashPreimage field does not push-data-frame its \
         continuation state (len {} vs ByteString's {})",
        got.len(),
        control.len()
    );
    assert_eq!(
        got, control,
        "a mutable SigHashPreimage field does not frame its continuation like ByteString"
    );
}

/// Negative controls — without these the two tests above would still pass if
/// every state type collapsed onto the same lowering.
#[test]
fn fixed_width_state_types_are_not_push_data_framed() {
    let control = control_hex();
    for prop_type in ["RabinSig", "RabinPubKey", "PubKey"] {
        assert_ne!(
            script_hex(&write_src(prop_type), WRITE_FILE),
            control,
            "{} compiled identically to ByteString — it must keep its fixed-width framing",
            prop_type
        );
    }
}
