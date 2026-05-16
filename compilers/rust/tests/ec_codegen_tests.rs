//! EC (secp256k1) codegen unit tests for the Rust compiler.
//!
//! Mirrors the spirit of `compilers/go/codegen/*` codegen tests for the
//! EC primitive emitters. These are sanity checks that each emit_ec_*
//! entry point produces a non-empty, deterministic StackOp sequence —
//! cross-compiler byte-equality is enforced separately by the conformance
//! suite. We keep these tests in-process so EC emitter regressions surface
//! inside the Rust crate's own `cargo test` run.

use runar_compiler_rust::codegen::ec::{
    emit_ec_add, emit_ec_encode_compressed, emit_ec_make_point, emit_ec_mod_reduce,
    emit_ec_mul, emit_ec_mul_gen, emit_ec_negate, emit_ec_on_curve, emit_ec_point_x,
    emit_ec_point_y, emit_reverse_32,
};
use runar_compiler_rust::codegen::stack::StackOp;

fn collect<F: FnOnce(&mut dyn FnMut(StackOp))>(f: F) -> Vec<StackOp> {
    let mut ops: Vec<StackOp> = Vec::new();
    {
        let mut sink = |op: StackOp| ops.push(op);
        f(&mut sink);
    }
    ops
}

// ---------------------------------------------------------------------------
// Each emitter produces non-empty output
// ---------------------------------------------------------------------------

#[test]
fn test_emit_reverse_32_nontrivial() {
    let ops = collect(|s| emit_reverse_32(s));
    assert!(!ops.is_empty(), "emit_reverse_32 should not be empty");
}

#[test]
fn test_emit_ec_add_nontrivial() {
    let ops = collect(|s| emit_ec_add(s));
    assert!(ops.len() > 10, "ec_add should emit a substantial program, got {}", ops.len());
}

#[test]
fn test_emit_ec_mul_nontrivial() {
    let ops = collect(|s| emit_ec_mul(s));
    assert!(ops.len() > 100, "ec_mul should emit a large program, got {}", ops.len());
}

#[test]
fn test_emit_ec_mul_gen_nontrivial() {
    let ops = collect(|s| emit_ec_mul_gen(s));
    assert!(!ops.is_empty(), "ec_mul_gen should not be empty");
}

#[test]
fn test_emit_ec_negate_nontrivial() {
    let ops = collect(|s| emit_ec_negate(s));
    assert!(!ops.is_empty(), "ec_negate should not be empty");
}

#[test]
fn test_emit_ec_on_curve_nontrivial() {
    let ops = collect(|s| emit_ec_on_curve(s));
    assert!(!ops.is_empty(), "ec_on_curve should not be empty");
}

#[test]
fn test_emit_ec_mod_reduce_nontrivial() {
    let ops = collect(|s| emit_ec_mod_reduce(s));
    assert!(!ops.is_empty(), "ec_mod_reduce should not be empty");
}

#[test]
fn test_emit_ec_encode_compressed_nontrivial() {
    let ops = collect(|s| emit_ec_encode_compressed(s));
    assert!(!ops.is_empty(), "ec_encode_compressed should not be empty");
}

#[test]
fn test_emit_ec_make_point_nontrivial() {
    let ops = collect(|s| emit_ec_make_point(s));
    assert!(!ops.is_empty(), "ec_make_point should not be empty");
}

#[test]
fn test_emit_ec_point_x_nontrivial() {
    let ops = collect(|s| emit_ec_point_x(s));
    assert!(!ops.is_empty(), "ec_point_x should not be empty");
}

#[test]
fn test_emit_ec_point_y_nontrivial() {
    let ops = collect(|s| emit_ec_point_y(s));
    assert!(!ops.is_empty(), "ec_point_y should not be empty");
}

// ---------------------------------------------------------------------------
// Determinism: each emitter is pure
// ---------------------------------------------------------------------------

fn sig(ops: &[StackOp]) -> String {
    format!("{:?}", ops)
}

#[test]
fn test_emit_ec_add_deterministic() {
    let a = collect(|s| emit_ec_add(s));
    let b = collect(|s| emit_ec_add(s));
    assert_eq!(sig(&a), sig(&b), "emit_ec_add should be deterministic");
}

#[test]
fn test_emit_ec_mul_deterministic() {
    let a = collect(|s| emit_ec_mul(s));
    let b = collect(|s| emit_ec_mul(s));
    assert_eq!(sig(&a), sig(&b), "emit_ec_mul should be deterministic");
}

#[test]
fn test_emit_reverse_32_deterministic() {
    let a = collect(|s| emit_reverse_32(s));
    let b = collect(|s| emit_reverse_32(s));
    assert_eq!(sig(&a), sig(&b), "emit_reverse_32 should be deterministic");
}

// ---------------------------------------------------------------------------
// T-11: Op-count goldens for every EC emitter.
//
// The existing _nontrivial tests above only assert `ops.len() > 0` (or > N).
// These goldens lock the exact op count for each Rust emitter so codegen
// drift surfaces as a localized regression rather than only as a cross-tier
// hex mismatch in the conformance harness. The counts match the Python /
// TS / Java peers for every emitter EXCEPT ecMul / ecMulGen — those two
// emit 4 fewer raw StackOps in the Rust tier than the other six (63824 /
// 63826 vs the peer 63828 / 63830). The final compiled hex is still
// byte-identical across all 7 tiers (enforced by the conformance harness),
// so the divergence is in the pre-peephole StackOp granularity, not in
// emitted opcodes — but it is real and pinned here so any further drift
// fails locally.
//
// To update goldens after an intentional codegen change, run the Java peer
// EcTest and the Python peer test_ec.py, copy the new numbers, and update
// every tier together.
// ---------------------------------------------------------------------------

#[test]
fn test_ec_add_op_count_golden() {
    let ops = collect(|s| emit_ec_add(s));
    assert_eq!(ops.len(), 8078, "ecAdd op count drift");
}

#[test]
fn test_ec_mul_op_count_golden() {
    let ops = collect(|s| emit_ec_mul(s));
    // Rust emits 4 fewer raw StackOps than the Python/TS/Java peer; see the
    // module-level comment above. Final hex is byte-identical.
    assert_eq!(ops.len(), 63824, "ecMul op count drift");
}

#[test]
fn test_ec_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_ec_mul_gen(s));
    // Rust emits 4 fewer raw StackOps than the Python/TS/Java peer; see the
    // module-level comment above. Final hex is byte-identical.
    assert_eq!(ops.len(), 63826, "ecMulGen op count drift");
}

#[test]
fn test_ec_negate_op_count_golden() {
    let ops = collect(|s| emit_ec_negate(s));
    assert_eq!(ops.len(), 945, "ecNegate op count drift");
}

#[test]
fn test_ec_on_curve_op_count_golden() {
    let ops = collect(|s| emit_ec_on_curve(s));
    assert_eq!(ops.len(), 520, "ecOnCurve op count drift");
}

#[test]
fn test_ec_mod_reduce_op_count_golden() {
    let ops = collect(|s| emit_ec_mod_reduce(s));
    assert_eq!(ops.len(), 8, "ecModReduce op count drift");
}

#[test]
fn test_ec_encode_compressed_op_count_golden() {
    let ops = collect(|s| emit_ec_encode_compressed(s));
    assert_eq!(ops.len(), 14, "ecEncodeCompressed op count drift");
}

#[test]
fn test_ec_make_point_op_count_golden() {
    let ops = collect(|s| emit_ec_make_point(s));
    assert_eq!(ops.len(), 467, "ecMakePoint op count drift");
}

#[test]
fn test_ec_point_x_op_count_golden() {
    let ops = collect(|s| emit_ec_point_x(s));
    assert_eq!(ops.len(), 233, "ecPointX op count drift");
}

#[test]
fn test_ec_point_y_op_count_golden() {
    let ops = collect(|s| emit_ec_point_y(s));
    assert_eq!(ops.len(), 234, "ecPointY op count drift");
}

// Representative byte/shape assertion for the smallest emitter — ecModReduce
// is exactly 8 ops in a known sequence. Mirrors the Python peer
// `test_ec_mod_reduce_is_exact_eight_ops`.
#[test]
fn test_ec_mod_reduce_exact_op_shape() {
    let ops = collect(|s| emit_ec_mod_reduce(s));
    assert_eq!(ops.len(), 8);
    // Render with the Debug format and check the load-bearing tokens.
    // Avoids depending on private enum variant fields that differ subtly
    // across Rust/Python/Java.
    let rendered = format!("{:?}", ops);
    assert!(rendered.contains("OP_2DUP"), "expected OP_2DUP token, got: {}", rendered);
    assert!(rendered.contains("OP_ADD"), "expected OP_ADD token, got: {}", rendered);
    // Two OP_MOD occurrences (positions 1 and 7 in the Python peer).
    let mod_count = rendered.matches("OP_MOD").count();
    assert!(mod_count >= 2, "expected ≥2 OP_MOD tokens, got {} in: {}", mod_count, rendered);
}
