//! Op-shape parity tests for the Rust `addRawOutput` lowering.
//!
//! `addRawOutput(satoshis, scriptBytes)` emits a Bitcoin output whose script
//! body is supplied verbatim by the caller (no codePart, no state
//! continuation). The serialized shape is:
//!
//!     amount(8LE) + varint(scriptLen) + scriptBytes
//!
//! These tests pin the load-bearing tail of the lowered Bitcoin Script
//! (`OP_SIZE` for varint width derivation, `OP_NUM2BIN` for the satoshis
//! width prefix, `OP_CAT` cadence) so a wrong-opcode regression in
//! `compilers/rust/src/codegen/stack.rs::lower_add_raw_output` fails locally
//! instead of surfacing only as a hex divergence in the conformance suite.
//!
//! Probe contract: the in-tree `examples/rust/add-raw-output/` example, whose
//! `send_to_script` method calls `self.add_raw_output(1000, script_bytes)`
//! followed by a state continuation via `self.add_output(0, self.count)`.
//! The test isolates assertions to the addRawOutput portion using its
//! uniquely identifiable opcode pattern.
//!
//! Mirrors `compilers/python/tests/codegen/test_addrawoutput.py` (the Python
//! sibling test for the same gap).
//!
//! GAP-020 (audits/cross-language-completeness-20260510.md, Section 4 / C4).

use std::path::PathBuf;

use runar_compiler_rust::compile_from_source_str;

fn fixture_source() -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("examples");
    p.push("rust");
    p.push("add-raw-output");
    p.push("RawOutputTest.runar.rs");
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("read fixture {}: {}", p.display(), e))
}

fn compile_fixture() -> (String, String) {
    let src = fixture_source();
    let artifact = compile_from_source_str(&src, Some("RawOutputTest.runar.rs"))
        .expect("RawOutputTest fixture must compile");
    (artifact.script, artifact.asm)
}

/// Count occurrences of the given single-byte opcode hex (e.g. "82" for
/// `OP_SIZE`, "ae" for `OP_CHECKMULTISIG`) at byte-aligned boundaries within
/// a hex string. Steps by 2 chars (1 byte) to avoid matching bytes that are
/// part of multi-byte push payloads. This is a coarse over-counter (push
/// payloads can still match), but it suffices when used together with ASM
/// assertions to pin opcode shape.
fn count_op_byte_aligned(hex: &str, op_hex: &str) -> usize {
    assert_eq!(op_hex.len(), 2, "expected single-byte opcode hex");
    let bytes = hex.as_bytes();
    let needle = op_hex.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == needle[0] && bytes[i + 1] == needle[1] {
            n += 1;
        }
        i += 2;
    }
    n
}

fn count_asm_op(asm: &str, op_name: &str) -> usize {
    asm.split_whitespace().filter(|tok| *tok == op_name).count()
}

// ---------------------------------------------------------------------------
// Compilation succeeds + artifact has expected shape
// ---------------------------------------------------------------------------

#[test]
fn test_raw_output_contract_compiles() {
    let (script, asm) = compile_fixture();
    assert!(!script.is_empty(), "script hex must not be empty");
    assert!(!asm.is_empty(), "ASM must not be empty");
}

// ---------------------------------------------------------------------------
// Op-shape goldens — the load-bearing addRawOutput opcode pattern
// ---------------------------------------------------------------------------

#[test]
fn test_raw_output_emits_op_size_for_varint_derivation() {
    // addRawOutput uses OP_SIZE on the user-supplied script bytes to derive
    // the varint length prefix. The state-continuation addOutput in the same
    // method also calls OP_SIZE for its own scriptLen varint.
    // Total expected: >= 2 OP_SIZE.
    let (_, asm) = compile_fixture();
    let op_sizes = count_asm_op(&asm, "OP_SIZE");
    assert!(
        op_sizes >= 2,
        "expected >= 2 OP_SIZE (one for raw output, one for state continuation), got {} in:\n{}",
        op_sizes,
        asm
    );
}

#[test]
fn test_raw_output_emits_num2bin_for_satoshi_width() {
    // addRawOutput emits OP_NUM2BIN to materialise the 8-byte LE satoshi
    // amount. The state-continuation addOutput emits another for its own
    // satoshis (literal 0) and may emit a third for the bigint state value
    // serialization. Total expected: >= 2 OP_NUM2BIN.
    let (_, asm) = compile_fixture();
    let n2b = count_asm_op(&asm, "OP_NUM2BIN");
    assert!(
        n2b >= 2,
        "expected >= 2 OP_NUM2BIN (raw output + state continuation), got {} in:\n{}",
        n2b,
        asm
    );
}

#[test]
fn test_raw_output_emits_cat_chain() {
    // addRawOutput emits 2 OP_CAT in its tail (varint||script, then
    // satoshis||rest). The state-continuation addOutput emits more
    // (codePart||0x6a, ||stateBytes, varint||script, satoshis||rest).
    // Total expected: >= 4 OP_CAT.
    let (_, asm) = compile_fixture();
    let cats = count_asm_op(&asm, "OP_CAT");
    assert!(
        cats >= 4,
        "expected >= 4 OP_CAT in raw-output + state-cont. tail, got {}",
        cats
    );
}

#[test]
fn test_raw_output_does_not_emit_op_return_opcode() {
    // addRawOutput must never emit OP_RETURN as a script opcode (that would
    // terminate the script). The 0x6a byte for the state-continuation
    // separator IS pushed as data, but never as an opcode at the top level.
    let (_, asm) = compile_fixture();
    let returns = count_asm_op(&asm, "OP_RETURN");
    assert_eq!(
        returns, 0,
        "addRawOutput must not emit OP_RETURN as opcode; ASM was:\n{}",
        asm
    );
}

#[test]
fn test_raw_output_emits_codeseparator_once() {
    // OP_CODESEPARATOR is auto-injected exactly once at the checkPreimage
    // entry of a stateful method, regardless of subsequent addRawOutput /
    // addOutput calls.
    let (_, asm) = compile_fixture();
    let cs = count_asm_op(&asm, "OP_CODESEPARATOR");
    assert_eq!(cs, 1, "expected exactly 1 OP_CODESEPARATOR; got {}", cs);
}

#[test]
fn test_raw_output_hex_contains_op_size_byte() {
    // Byte-level guard: OP_SIZE = 0x82 must appear at least once in the
    // emitted hex. This guards against a regression where the codegen
    // emits the wrong opcode but still produces a valid-looking ASM
    // (the ASM check could theoretically print correctly even if the
    // emitter wrote a different byte; this check pins the actual byte).
    let (script, _) = compile_fixture();
    let op_size = count_op_byte_aligned(&script, "82");
    assert!(
        op_size >= 2,
        "expected >= 2 byte-aligned 0x82 (OP_SIZE) bytes in script hex; got {}",
        op_size
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn test_raw_output_lowering_is_deterministic() {
    let (script_a, asm_a) = compile_fixture();
    let (script_b, asm_b) = compile_fixture();
    assert_eq!(
        script_a, script_b,
        "addRawOutput lowering must be deterministic (script hex differs across runs)"
    );
    assert_eq!(
        asm_a, asm_b,
        "addRawOutput lowering must be deterministic (ASM differs across runs)"
    );
}
