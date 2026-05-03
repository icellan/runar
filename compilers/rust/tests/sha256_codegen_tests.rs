//! SHA-256 codegen unit tests for the Rust compiler.
//!
//! Mirrors `compilers/go/codegen/sha256_test.go` patterns: invokes the public
//! emit_sha256_compress / emit_sha256_finalize emitters and asserts they
//! produce non-trivial, well-formed StackOp sequences. The cross-compiler
//! conformance suite already verifies byte-equality with the TS reference;
//! these tests are an in-process sanity gate so the emitter regressions
//! surface as unit-test failures inside the Rust crate itself.

use runar_compiler_rust::codegen::sha256::{emit_sha256_compress, emit_sha256_finalize};
use runar_compiler_rust::codegen::stack::{PushValue, StackOp};

fn collect_emit<F: FnOnce(&mut dyn FnMut(StackOp))>(f: F) -> Vec<StackOp> {
    let mut ops = Vec::new();
    {
        let mut sink = |op: StackOp| ops.push(op);
        f(&mut sink);
    }
    ops
}

fn count_opcode(ops: &[StackOp], code: &str) -> usize {
    ops.iter()
        .filter(|op| matches!(op, StackOp::Opcode(c) if c == code))
        .count()
}

fn count_pushes(ops: &[StackOp]) -> usize {
    ops.iter()
        .filter(|op| matches!(op, StackOp::Push(_)))
        .count()
}

// ---------------------------------------------------------------------------
// emit_sha256_compress — public entry point
// ---------------------------------------------------------------------------

#[test]
fn test_sha256_compress_emits_nontrivial_program() {
    let ops = collect_emit(|sink| emit_sha256_compress(sink));
    assert!(
        ops.len() > 100,
        "SHA-256 compress should emit a substantial program, got {} ops",
        ops.len()
    );
}

#[test]
fn test_sha256_compress_uses_arithmetic_opcodes() {
    let ops = collect_emit(|sink| emit_sha256_compress(sink));
    // SHA-256 compression is heavy on additions and bitwise ops.
    assert!(count_opcode(&ops, "OP_ADD") > 0, "expected OP_ADD opcodes");
}

#[test]
fn test_sha256_compress_pushes_constants() {
    let ops = collect_emit(|sink| emit_sha256_compress(sink));
    // SHA-256 has 64 round constants and 8 IV words; expect many pushes.
    assert!(count_pushes(&ops) > 0, "expected push values");
}

// ---------------------------------------------------------------------------
// emit_sha256_finalize — public entry point
// ---------------------------------------------------------------------------

#[test]
fn test_sha256_finalize_emits_nontrivial_program() {
    let ops = collect_emit(|sink| emit_sha256_finalize(sink));
    assert!(
        ops.len() > 50,
        "SHA-256 finalize should emit a non-trivial program, got {} ops",
        ops.len()
    );
}

#[test]
fn test_sha256_finalize_uses_num2bin() {
    let ops = collect_emit(|sink| emit_sha256_finalize(sink));
    // Finalization needs OP_NUM2BIN to materialise the 8-byte big-endian
    // bit-length tail of the padded message.
    assert!(
        count_opcode(&ops, "OP_NUM2BIN") > 0,
        "expected OP_NUM2BIN in finalize emit"
    );
}

#[test]
fn test_sha256_finalize_uses_cat_or_split() {
    let ops = collect_emit(|sink| emit_sha256_finalize(sink));
    // Finalization assembles the padded final block via concatenation /
    // splitting.
    let cat_or_split =
        count_opcode(&ops, "OP_CAT") + count_opcode(&ops, "OP_SPLIT");
    assert!(
        cat_or_split > 0,
        "expected OP_CAT / OP_SPLIT in finalize emit"
    );
}

#[test]
fn test_sha256_finalize_pushes_padding_constant() {
    let ops = collect_emit(|sink| emit_sha256_finalize(sink));
    // The 0x80 padding byte must appear as a literal byte push.
    let has_pad = ops.iter().any(|op| match op {
        StackOp::Push(PushValue::Bytes(b)) => b.contains(&0x80),
        _ => false,
    });
    assert!(has_pad, "expected 0x80 padding byte in finalize emit");
}

// ---------------------------------------------------------------------------
// Determinism: two consecutive emits are byte-identical
// ---------------------------------------------------------------------------

fn ops_signature(ops: &[StackOp]) -> String {
    // StackOp does not implement PartialEq; compare via Debug strings.
    format!("{:?}", ops)
}

#[test]
fn test_sha256_compress_is_deterministic() {
    let a = collect_emit(|sink| emit_sha256_compress(sink));
    let b = collect_emit(|sink| emit_sha256_compress(sink));
    assert_eq!(
        a.len(),
        b.len(),
        "emit_sha256_compress should be deterministic in op count"
    );
    assert_eq!(
        ops_signature(&a),
        ops_signature(&b),
        "emit_sha256_compress should produce identical ops"
    );
}

#[test]
fn test_sha256_finalize_is_deterministic() {
    let a = collect_emit(|sink| emit_sha256_finalize(sink));
    let b = collect_emit(|sink| emit_sha256_finalize(sink));
    assert_eq!(a.len(), b.len(), "emit_sha256_finalize should be deterministic");
    assert_eq!(ops_signature(&a), ops_signature(&b));
}
