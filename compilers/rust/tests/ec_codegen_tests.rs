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
