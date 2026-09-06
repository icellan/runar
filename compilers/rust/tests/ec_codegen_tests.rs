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

/// Total number of `StackOp`s in `ops`, INCLUDING the bodies of `if` ops.
///
/// A flat `ops.len()` cannot see inside a branch, so any emitter whose work
/// sits in an `if` body — the scalar ladders emit 257 / 385 conditional
/// additions, WOTS+ and SLH-DSA are almost entirely conditional — reports a
/// count that barely moves no matter what the branch contains. Adding +1.3 KB
/// of script inside the ladder's last step left the `p256_mul` / `p384_mul`
/// goldens byte-identical. Recursing is what makes the golden a gate.
fn count_op_tree(ops: &[StackOp]) -> usize {
    let mut total = 0usize;
    for op in ops {
        total += 1;
        if let StackOp::If { then_ops, else_ops } = op {
            total += count_op_tree(then_ops);
            total += count_op_tree(else_ops);
        }
    }
    total
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
    let ops = collect(|s| emit_ec_add(s, None));
    assert!(ops.len() > 10, "ec_add should emit a substantial program, got {}", ops.len());
}

#[test]
fn test_emit_ec_mul_nontrivial() {
    let ops = collect(|s| emit_ec_mul(s, None));
    assert!(ops.len() > 100, "ec_mul should emit a large program, got {}", ops.len());
}

#[test]
fn test_emit_ec_mul_gen_nontrivial() {
    let ops = collect(|s| emit_ec_mul_gen(s, None));
    assert!(!ops.is_empty(), "ec_mul_gen should not be empty");
}

#[test]
fn test_emit_ec_negate_nontrivial() {
    let ops = collect(|s| emit_ec_negate(s, None));
    assert!(!ops.is_empty(), "ec_negate should not be empty");
}

#[test]
fn test_emit_ec_on_curve_nontrivial() {
    let ops = collect(|s| emit_ec_on_curve(s, None));
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
    let a = collect(|s| emit_ec_add(s, None));
    let b = collect(|s| emit_ec_add(s, None));
    assert_eq!(sig(&a), sig(&b), "emit_ec_add should be deterministic");
}

#[test]
fn test_emit_ec_mul_deterministic() {
    let a = collect(|s| emit_ec_mul(s, None));
    let b = collect(|s| emit_ec_mul(s, None));
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
// hex mismatch in the conformance harness. The counts match the Go / Python
// / TS / Java peers for every emitter.
//
// They did not always: ecMul / ecMulGen used to emit 4 fewer raw StackOps
// here than the other six tiers, because this tier pre-folded `k + 3n` into
// one `push 3n; OP_ADD` where everyone else emits three `push n; OP_ADD`
// steps. That private shortcut is gone (it is what made the cross-tier
// flag-parity comparison impossible to run in this tier), so the op tree now
// agrees with Go op-for-op.
//
// To update goldens after an intentional codegen change, run the Java peer
// EcTest and the Python peer test_ec.py, copy the new numbers, and update
// every tier together.
// ---------------------------------------------------------------------------

#[test]
fn test_ec_add_op_count_golden() {
    let ops = collect(|s| emit_ec_add(s, None));
    // 8202 -> 8223 (+21 ops / +21 bytes) over the pre-P==-Q-fix shape: the
    // second OP_NUMEQUAL on y, the OP_BOOLAND that folds it into `cond`, the
    // OP_SUB/OP_NOT that build `notinf`, the two OP_MULs that mask rx/ry, and
    // the picks/rolls feeding them. All 1-byte ops, so the op count and the
    // byte count move together.
    assert_eq!(count_op_tree(&ops), 8223, "ecAdd op count drift");
}

#[test]
fn test_ec_mul_op_count_golden() {
    let ops = collect(|s| emit_ec_mul(s, None));
    // +4 ops against the previous golden: `emit_ec_mul`'s `k + 3n` offset is
    // now three `push n; OP_ADD` steps instead of one pre-folded
    // `push 3n; OP_ADD`. The peephole's fold-chain-add collapses them back, so
    // the SCRIPT BYTES are unchanged (the conformance hex goldens are
    // untouched) and this count now matches Go's table entry exactly.
    assert_eq!(count_op_tree(&ops), 130515, "ecMul op count drift");
}

#[test]
fn test_ec_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_ec_mul_gen(s, None));
    // +4 ops against the previous golden: `emit_ec_mul`'s `k + 3n` offset is
    // now three `push n; OP_ADD` steps instead of one pre-folded
    // `push 3n; OP_ADD`. The peephole's fold-chain-add collapses them back, so
    // the SCRIPT BYTES are unchanged (the conformance hex goldens are
    // untouched) and this count now matches Go's table entry exactly.
    assert_eq!(count_op_tree(&ops), 130517, "ecMulGen op count drift");
}

#[test]
fn test_ec_negate_op_count_golden() {
    let ops = collect(|s| emit_ec_negate(s, None));
    assert_eq!(count_op_tree(&ops), 945, "ecNegate op count drift");
}

#[test]
fn test_ec_on_curve_op_count_golden() {
    let ops = collect(|s| emit_ec_on_curve(s, None));
    assert_eq!(count_op_tree(&ops), 533, "ecOnCurve op count drift");
}

#[test]
fn test_ec_mod_reduce_op_count_golden() {
    let ops = collect(|s| emit_ec_mod_reduce(s));
    assert_eq!(count_op_tree(&ops), 8, "ecModReduce op count drift");
}

#[test]
fn test_ec_encode_compressed_op_count_golden() {
    let ops = collect(|s| emit_ec_encode_compressed(s));
    assert_eq!(count_op_tree(&ops), 16, "ecEncodeCompressed op count drift");
}

#[test]
fn test_ec_make_point_op_count_golden() {
    let ops = collect(|s| emit_ec_make_point(s));
    assert_eq!(count_op_tree(&ops), 467, "ecMakePoint op count drift");
}

#[test]
fn test_ec_point_x_op_count_golden() {
    let ops = collect(|s| emit_ec_point_x(s));
    assert_eq!(count_op_tree(&ops), 233, "ecPointX op count drift");
}

#[test]
fn test_ec_point_y_op_count_golden() {
    let ops = collect(|s| emit_ec_point_y(s));
    assert_eq!(count_op_tree(&ops), 234, "ecPointY op count drift");
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
