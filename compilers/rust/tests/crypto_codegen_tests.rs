//! Cryptographic codegen unit tests for the Rust compiler — SLH-DSA, Blake3,
//! P-256, and P-384 emitters.
//!
//! These complement `sha256_codegen_tests.rs` and `ec_codegen_tests.rs` by
//! invoking the public emitters and asserting they produce non-trivial,
//! deterministic StackOp sequences. Cross-compiler byte-equality with the
//! TS reference is enforced by the conformance suite; these tests are an
//! in-process sanity gate.

use runar_compiler_rust::codegen::blake3::{emit_blake3_compress, emit_blake3_hash};
use runar_compiler_rust::codegen::p256_p384::{
    emit_p256_add, emit_p256_encode_compressed, emit_p256_mul, emit_p256_mul_gen,
    emit_p256_negate, emit_p256_on_curve, emit_p384_add, emit_p384_encode_compressed,
    emit_p384_mul, emit_p384_mul_gen, emit_p384_negate, emit_p384_on_curve,
    emit_verify_ecdsa_p256, emit_verify_ecdsa_p384,
};
use runar_compiler_rust::codegen::slh_dsa::emit_verify_slh_dsa;
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
// Blake3 codegen
// ---------------------------------------------------------------------------

#[test]
fn test_emit_blake3_compress_nontrivial() {
    let ops = collect(|s| emit_blake3_compress(s));
    assert!(
        ops.len() > 100,
        "blake3_compress should emit a substantial program, got {}",
        ops.len()
    );
}

#[test]
fn test_emit_blake3_hash_nontrivial() {
    let ops = collect(|s| emit_blake3_hash(s));
    assert!(
        ops.len() > 100,
        "blake3_hash should emit a substantial program, got {}",
        ops.len()
    );
}

fn sig(ops: &[StackOp]) -> String {
    format!("{:?}", ops)
}

#[test]
fn test_emit_blake3_compress_deterministic() {
    let a = collect(|s| emit_blake3_compress(s));
    let b = collect(|s| emit_blake3_compress(s));
    assert_eq!(sig(&a), sig(&b), "emit_blake3_compress should be deterministic");
}

// ---------------------------------------------------------------------------
// P-256 codegen
// ---------------------------------------------------------------------------

#[test]
fn test_emit_p256_add_nontrivial() {
    let ops = collect(|s| emit_p256_add(s));
    assert!(ops.len() > 10, "p256_add should emit a substantial program, got {}", ops.len());
}

#[test]
fn test_emit_p256_mul_nontrivial() {
    let ops = collect(|s| emit_p256_mul(s));
    assert!(ops.len() > 100, "p256_mul should emit a large program, got {}", ops.len());
}

#[test]
fn test_emit_p256_mul_gen_nontrivial() {
    let ops = collect(|s| emit_p256_mul_gen(s));
    assert!(!ops.is_empty(), "p256_mul_gen should not be empty");
}

#[test]
fn test_emit_p256_negate_nontrivial() {
    let ops = collect(|s| emit_p256_negate(s));
    assert!(!ops.is_empty(), "p256_negate should not be empty");
}

#[test]
fn test_emit_p256_on_curve_nontrivial() {
    let ops = collect(|s| emit_p256_on_curve(s));
    assert!(!ops.is_empty(), "p256_on_curve should not be empty");
}

#[test]
fn test_emit_p256_encode_compressed_nontrivial() {
    let ops = collect(|s| emit_p256_encode_compressed(s));
    assert!(!ops.is_empty(), "p256_encode_compressed should not be empty");
}

#[test]
fn test_emit_verify_ecdsa_p256_nontrivial() {
    let ops = collect(|s| emit_verify_ecdsa_p256(s));
    assert!(
        ops.len() > 100,
        "verify_ecdsa_p256 should emit a substantial program, got {}",
        ops.len()
    );
}

// ---------------------------------------------------------------------------
// P-384 codegen
// ---------------------------------------------------------------------------

#[test]
fn test_emit_p384_add_nontrivial() {
    let ops = collect(|s| emit_p384_add(s));
    assert!(ops.len() > 10, "p384_add should emit a substantial program, got {}", ops.len());
}

#[test]
fn test_emit_p384_mul_nontrivial() {
    let ops = collect(|s| emit_p384_mul(s));
    assert!(ops.len() > 100, "p384_mul should emit a large program, got {}", ops.len());
}

#[test]
fn test_emit_p384_mul_gen_nontrivial() {
    let ops = collect(|s| emit_p384_mul_gen(s));
    assert!(!ops.is_empty(), "p384_mul_gen should not be empty");
}

#[test]
fn test_emit_p384_negate_nontrivial() {
    let ops = collect(|s| emit_p384_negate(s));
    assert!(!ops.is_empty(), "p384_negate should not be empty");
}

#[test]
fn test_emit_p384_on_curve_nontrivial() {
    let ops = collect(|s| emit_p384_on_curve(s));
    assert!(!ops.is_empty(), "p384_on_curve should not be empty");
}

#[test]
fn test_emit_p384_encode_compressed_nontrivial() {
    let ops = collect(|s| emit_p384_encode_compressed(s));
    assert!(!ops.is_empty(), "p384_encode_compressed should not be empty");
}

#[test]
fn test_emit_verify_ecdsa_p384_nontrivial() {
    let ops = collect(|s| emit_verify_ecdsa_p384(s));
    assert!(
        ops.len() > 100,
        "verify_ecdsa_p384 should emit a substantial program, got {}",
        ops.len()
    );
}

// ---------------------------------------------------------------------------
// SLH-DSA codegen
// ---------------------------------------------------------------------------

#[test]
fn test_emit_verify_slh_dsa_128s_nontrivial() {
    let ops = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    // SLH-DSA scripts are very large (>100k ops for 128s).
    assert!(
        ops.len() > 10_000,
        "verify_slh_dsa SHA2_128s should emit a huge program, got {}",
        ops.len()
    );
}

#[test]
fn test_emit_verify_slh_dsa_128s_baseline() {
    // SHA2_128s is the parameter set used by examples and integration tests
    // (see PostQuantumSLHDSANaiveInsecure / SPHINCSWallet). All six FIPS 205
    // SHA-2 parameter sets are exercised by
    // `test_emit_verify_slh_dsa_all_param_sets` below.
    let ops = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    assert!(
        ops.len() > 10_000,
        "verify_slh_dsa SHA2_128s should emit a huge program, got {}",
        ops.len()
    );
}

#[test]
fn test_emit_verify_slh_dsa_deterministic() {
    let a = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    let b = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    assert_eq!(a.len(), b.len(), "emit_verify_slh_dsa should be deterministic");
    assert_eq!(sig(&a), sig(&b));
}

/// Cross-language byte-equality canary: the Rust StackOp counts for every
/// FIPS 205 SHA-2 parameter set must match the Go reference implementation.
/// These numbers come from running the equivalent loop against
/// `compilers/go/codegen` (see `EmitVerifySLHDSA`). Go and TS are the
/// golden references; deviation indicates the Rust port has drifted.
#[test]
fn test_emit_verify_slh_dsa_op_counts_match_go_reference() {
    // (key, expected_op_count_from_go)
    let expected = [
        ("SHA2_128s", 29559usize),
        ("SHA2_128f", 85761),
        ("SHA2_192s", 41899),
        ("SHA2_192f", 121708),
        ("SHA2_256s", 61123),
        ("SHA2_256f", 122993),
    ];
    for (key, want) in expected {
        let ops = collect(|s| emit_verify_slh_dsa(s, key));
        assert_eq!(
            ops.len(),
            want,
            "verify_slh_dsa {} op count diverged from Go reference",
            key
        );
    }
}

/// Regression test for the `emit_slh_fors` arithmetic underflow.
///
/// `right_shift = total_bits - bit_offset - a` was computed in `usize`
/// (unsigned), which panicked in debug builds (and silently wrapped in
/// release) for parameter sets where `bit_offset + a > total_bits` during
/// any iteration of the FORS loop.
///
/// All six FIPS 205 SHA-2 parameter sets must emit a non-trivial,
/// deterministic StackOp program. Pre-fix, any of `SHA2_128f`,
/// `SHA2_192s`, `SHA2_192f`, `SHA2_256s`, `SHA2_256f` could panic.
#[test]
fn test_emit_verify_slh_dsa_all_param_sets() {
    let sets = [
        "SHA2_128s",
        "SHA2_128f",
        "SHA2_192s",
        "SHA2_192f",
        "SHA2_256s",
        "SHA2_256f",
    ];
    for key in sets {
        let ops = collect(|s| emit_verify_slh_dsa(s, key));
        assert!(
            ops.len() > 10_000,
            "verify_slh_dsa {} should emit a huge program, got {}",
            key,
            ops.len()
        );
        // Determinism: a second call must produce the identical sequence.
        let again = collect(|s| emit_verify_slh_dsa(s, key));
        assert_eq!(
            ops.len(),
            again.len(),
            "verify_slh_dsa {} non-deterministic op count",
            key
        );
        assert_eq!(
            sig(&ops),
            sig(&again),
            "verify_slh_dsa {} non-deterministic op sequence",
            key
        );
    }
}

// ---------------------------------------------------------------------------
// T-11: Op-count goldens for the non-EC crypto emitters.
//
// The _nontrivial tests above only assert `ops.len() > 0` (or > N).
// These goldens lock the exact op count for each Rust emitter so codegen
// drift surfaces as a localized regression rather than only as a cross-tier
// hex mismatch in the conformance harness. Numbers mirror the Python peer
// (compilers/python/tests/codegen/test_p256_p384.py, test_blake3.py); any
// drift here typically indicates a real codegen change worth reviewing.
// Rust pre-peephole StackOp granularity can differ slightly from the
// other tiers; in that case keep this golden at the Rust value and note
// it (see ecMul / ecMulGen in `ec_codegen_tests.rs` for the precedent).
// ---------------------------------------------------------------------------

// -- Blake3 ----------------------------------------------------------------

#[test]
fn test_blake3_compress_op_count_golden() {
    let ops = collect(|s| emit_blake3_compress(s));
    assert_eq!(ops.len(), 10819, "blake3_compress op count drift");
}

#[test]
fn test_blake3_hash_op_count_golden() {
    let ops = collect(|s| emit_blake3_hash(s));
    assert_eq!(ops.len(), 10829, "blake3_hash op count drift");
}

// -- P-256 -----------------------------------------------------------------

#[test]
fn test_p256_add_op_count_golden() {
    let ops = collect(|s| emit_p256_add(s));
    assert_eq!(ops.len(), 6505, "p256_add op count drift");
}

#[test]
fn test_p256_mul_op_count_golden() {
    let ops = collect(|s| emit_p256_mul(s));
    // Rust emits 4 fewer raw StackOps than Python/Java peers; same pattern
    // as ecMul (see ec_codegen_tests.rs module comment). Final hex is
    // byte-identical (enforced by the conformance harness).
    assert_eq!(ops.len(), 73302, "p256_mul op count drift");
}

#[test]
fn test_p256_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_p256_mul_gen(s));
    // See p256_mul_op_count_golden comment.
    assert_eq!(ops.len(), 73304, "p256_mul_gen op count drift");
}

#[test]
fn test_p256_negate_op_count_golden() {
    let ops = collect(|s| emit_p256_negate(s));
    assert_eq!(ops.len(), 945, "p256_negate op count drift");
}

#[test]
fn test_p256_on_curve_op_count_golden() {
    let ops = collect(|s| emit_p256_on_curve(s));
    assert_eq!(ops.len(), 546, "p256_on_curve op count drift");
}

#[test]
fn test_p256_encode_compressed_op_count_golden() {
    let ops = collect(|s| emit_p256_encode_compressed(s));
    assert_eq!(ops.len(), 14, "p256_encode_compressed op count drift");
}

#[test]
fn test_verify_ecdsa_p256_op_count_golden() {
    let ops = collect(|s| emit_verify_ecdsa_p256(s));
    // Rust emits 8 fewer raw StackOps than Python/Java peers (a verify
    // computes two mul/mul_gen invocations × the 4-op divergence).
    assert_eq!(ops.len(), 163581, "verify_ecdsa_p256 op count drift");
}

// -- P-384 -----------------------------------------------------------------

#[test]
fn test_p384_add_op_count_golden() {
    let ops = collect(|s| emit_p384_add(s));
    assert_eq!(ops.len(), 11311, "p384_add op count drift");
}

#[test]
fn test_p384_mul_op_count_golden() {
    let ops = collect(|s| emit_p384_mul(s));
    // See ec_codegen_tests.rs module comment for the 4-op divergence pattern.
    assert_eq!(ops.len(), 111420, "p384_mul op count drift");
}

#[test]
fn test_p384_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_p384_mul_gen(s));
    // See p384_mul_op_count_golden comment.
    assert_eq!(ops.len(), 111422, "p384_mul_gen op count drift");
}

#[test]
fn test_p384_negate_op_count_golden() {
    let ops = collect(|s| emit_p384_negate(s));
    assert_eq!(ops.len(), 1393, "p384_negate op count drift");
}
