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

// F-338: emit_verify_ecdsa_p384 is the largest emitter in this crate (453K+
// tree ops) and, unlike its p384_add/p384_mul/p384_mul_gen/p384_negate
// siblings above and verify_ecdsa_p256 below, had NO count_op_tree golden —
// only the ops.len() > 100 threshold test above, which cannot detect a
// regression confined to an `if` branch body (see count_op_tree's doc
// comment) or indeed almost any regression, since the real program is 4500x
// the threshold. Verified: injecting one extra StackOp at the end of
// emit_verify_ecdsa_p384 left test_emit_verify_ecdsa_p384_nontrivial green.
//
// Cross-tier check: Go's countOpTree for EmitVerifyECDSA_P384 (not itself
// pinned in compilers/go/codegen/crypto_codegen_test.go, measured directly)
// is 453369, Δ8 from this tier's 453361. That Δ8 is the same raw-StackOp
// quirk already pinned and explained for verify_ecdsa_p256 above (Δ8 =
// "two mul/mul_gen invocations x the 4-op divergence" — see
// test_verify_ecdsa_p256_op_count_golden and the p256_mul/p384_mul comments):
// c_emit_verify_ecdsa calls the scalar-multiplication ladder (c_emit_mul,
// the same ladder p384_mul uses) twice internally (u1*G and u2*Q), same as
// p256, so it inherits the same per-ladder Δ4 x 2 = Δ8. Final
// script bytes are byte-identical across tiers (conformance/tests/p384-wallet
// exercises verifyECDSA_P384 end to end at 7-tier parity), confirming this is
// the known pre-peephole StackOp-count divergence, not a codegen bug.
#[test]
fn test_verify_ecdsa_p384_op_count_golden() {
    let ops = collect(|s| emit_verify_ecdsa_p384(s));
    assert_eq!(count_op_tree(&ops), 453361, "verify_ecdsa_p384 op count drift");
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

// F-385: this test used to be a byte-for-byte copy of
// `test_emit_verify_slh_dsa_128s_nontrivial` above (same `collect` call, same
// threshold, same message). All six valid FIPS 205 SHA-2 parameter sets are already
// exercised exhaustively — and more precisely — by
// `test_emit_verify_slh_dsa_op_counts_match_go_reference` below, so a second
// "does 128s emit something huge" check added no coverage.
//
// Repurposed to cover a nearby case nothing tests: `slh_params` (private to
// `slh_dsa.rs`, invoked at the top of `emit_verify_slh_dsa`) panics on any key
// outside the six FIPS 205 SHA-2 sets. No test exercised that guard.
#[test]
#[should_panic(expected = "Unknown SLH-DSA params: SHA2_512s")]
fn test_emit_verify_slh_dsa_unknown_param_set_panics() {
    let _ = collect(|s| emit_verify_slh_dsa(s, "SHA2_512s"));
}

#[test]
fn test_emit_verify_slh_dsa_deterministic() {
    let a = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    let b = collect(|s| emit_verify_slh_dsa(s, "SHA2_128s"));
    assert_eq!(a.len(), b.len(), "emit_verify_slh_dsa should be deterministic");
    assert_eq!(sig(&a), sig(&b));
}

/// Cross-language byte-equality canary: the Rust StackOp counts for every
/// FIPS 205 SHA-2 parameter set must match the Go/TS reference
/// implementations. Go and TS are the golden references; deviation
/// indicates the Rust port has drifted.
///
/// F-339: this canary used to pin the flat `ops.len()` -- exactly the metric
/// `count_op_tree`'s own doc comment (above) warns is blind inside an `if`
/// body, and WOTS+/SLH-DSA are almost entirely conditional. Verified by
/// temporarily injecting one extra `StackOp` into an `else` branch inside
/// `emit_slh_merkle`'s authentication-path loop (section 6, the XMSS root
/// computation) in `compilers/rust/src/codegen/slh_dsa.rs` (reverted after
/// the measurement): the OLD assertion (`ops.len()`), unmodified, still
/// reported `ok` because the mutated op never changed the length of the
/// top-level `Vec<StackOp>` -- only the branch body it lives inside -- while
/// the NEW assertion below (`count_op_tree`) went red (179322 vs 179259 for
/// SHA2_128s, h=63 loop iterations x 1 extra op). `count_op_tree` catches it
/// because it recurses into `StackOp::If` bodies, which is also why its
/// counts below are far larger than the old flat ones (e.g. SHA2_128s: 29577
/// flat vs 179259 tree).
///
/// Values cross-checked against both reference tiers for all six parameter
/// sets (not just the two Go/TS already pin as goldens:
/// compilers/go/codegen/crypto_codegen_test.go's TestSlhdsaEmitOpCountGoldens,
/// packages/runar-compiler/src/__tests__/slh-dsa-codegen.test.ts):
///   - Go: `countOpTree` run directly against `EmitVerifySLHDSA` for all six
///     sets (compilers/go/codegen, package-internal helper already used by
///     the pinned goldens).
///   - TS: `countOpTree` run directly against `emitVerifySLHDSA` for all six
///     sets (packages/runar-compiler/src/passes/slh-dsa-codegen.ts).
/// Go and TS agree with each other and with the counts below for every one
/// of the six sets; 128f/192s also match the pre-existing pinned Go/TS
/// goldens exactly (514175 / 256948).
#[test]
fn test_emit_verify_slh_dsa_op_counts_match_go_reference() {
    // Change history below predates F-339 and was measured under the OLD
    // flat `ops.len()` metric; kept as provenance, not as tree-count
    // arithmetic for the (much larger) values pinned further down.
    //
    // BUG-011: each verifySLHDSA_* prologue now emits an OP_SIZE exact-length
    // guard (+5 ops per parameter set) before the existing FORS / Merkle
    // path expansion. Counts updated in lockstep with the Go reference
    // (compilers/go/codegen/crypto_codegen_test.go).
    //
    // SLH-DSA codegen miscompile fix (audit #2): emit_slh_hmsg dropped one
    // reversing swap on the final multi-block MGF1 block (-1 op per set with a
    // >1-block digest: 128f/192f/256f/192s/256s), and emit_slh_fors now sizes
    // the FORS index window to ceil((bit_offset+a)/8) instead of capping at 2
    // bytes, so the a=14 sets (192s/256s) emit a 3-byte window on unlucky
    // alignments (+48 for 192s, +66 for 256s). Numbers match the Go/TS peers.
    //
    // #137 (FIPS-205 conformance) then added, per parameter set, exactly 6 + d:
    //   +6 once, in emit_slh_hmsg -- the MGF1 seed must be prefixed with
    //     R || PK.seed (FIPS 205 Sec 11.2.1): 2 extra copy_to_top (2 ops each)
    //     + 2 OP_CAT.
    //   +1 per hypertree layer (d layers) -- wots_pk_from_sig must restore the
    //     key pair address after set_type(WOTS_PK) (FIPS 205 Alg. 8 lines 8-11),
    //     turning a 1-op 4-zero-byte push into a 2-op push-depth + PICK.
    // d = 7, 22, 7, 22, 8, 17 for 128s, 128f, 192s, 192f, 256s, 256f.
    //
    // F-034: 256f now uses FIPS 205's FORS height a=9 (one more auth level
    // per FORS tree) and a 9-byte first tree-address encoding.
    //
    // F-339: switched the metric itself from flat `ops.len()` to
    // `count_op_tree`; see the function doc comment above for why and the
    // cross-tier check. (key, expected_op_tree_count_from_go_and_ts)
    let expected = [
        ("SHA2_128s", 179259usize),
        ("SHA2_128f", 514175),
        ("SHA2_192s", 256948),
        ("SHA2_192f", 741052),
        ("SHA2_256s", 350411),
        ("SHA2_256f", 703277),
    ];
    for (key, want) in expected {
        let ops = collect(|s| emit_verify_slh_dsa(s, key));
        assert_eq!(
            count_op_tree(&ops),
            want,
            "verify_slh_dsa {} op-tree count diverged from Go/TS reference",
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
    assert_eq!(count_op_tree(&ops), 10379, "blake3_compress op count drift");
}

#[test]
fn test_blake3_hash_op_count_golden() {
    let ops = collect(|s| emit_blake3_hash(s));
    assert_eq!(count_op_tree(&ops), 10387, "blake3_hash op count drift");
}

// -- P-256 -----------------------------------------------------------------

#[test]
// R-052 / CL-BUG-095 — the Point width gate re-stamped the ten op-count pins
// below. Every delta equals the one the other six tiers measured independently:
// *Add +6 (two decompose_point call sites, 3 ops each), *Mul / *MulGen /
// *Negate +3 (one call site), *OnCurve +15 (the 9-op clamp-and-flag gate, the
// 3-op verify, the extra OP_BOOLAND folding `_len_ok` in, and 2 rolls), and
// verify_ecdsa_p256 +12 (four internal call sites). *EncodeCompressed is
// unmoved at 16: the gate adds 3 ops and the fixed-offset parity read removes 3.
//
// The ABSOLUTE numbers here stay lower than the TypeScript tier's for
// *Mul/*MulGen/verify_ecdsa (e.g. 140035 vs 140038). That gap is PRE-EXISTING
// and is a counting difference in this file's count_op_tree, not a byte
// divergence — the two tiers emit byte-identical script, which the conformance
// runner proves at 78/78 with 0 inter-compiler mismatches. So these were
// re-stamped by applying the measured delta to this tier's own baseline, NOT by
// copying TypeScript's absolute values, which would have silently erased a
// difference that has nothing to do with this fix.
fn test_p256_add_op_count_golden() {
    let ops = collect(|s| emit_p256_add(s));
    // 6642 -> 6663 (+21 ops / +21 bytes) — the same delta ecAdd and p384Add
    // take, since all three share the affine-add structure: a second
    // OP_NUMEQUAL on y, the OP_BOOLAND folding it into `cond`, OP_SUB/OP_NOT
    // for `notinf`, two OP_MULs masking rx/ry, plus the picks/rolls feeding
    // them. Every one is a 1-byte op, so op count and byte count move together.
    // R-053 / CL-BUG-096 — the infinity-operand select adds another +50 here.
    // It replaces the four px/py/qx/qy drops and the two standalone `notinf`
    // OP_MULs with the pinf/qinf/usep/useq/user mask chain plus the six OP_MUL
    // and four OP_ADD selects and the picks/rolls feeding them. Measured on
    // this tier's own baseline, not copied from TypeScript.
    // N-252, the y = 0 tangent guard: pNNNAdd +12 (three picks + OP_SWAP OP_NOT OP_BOOLAND OP_BOOLAND OP_NOT OP_VERIFY); verifyECDSA_* +0, it does not take the guard.
    assert_eq!(count_op_tree(&ops), 6749, "p256_add op count drift");
}

#[test]
fn test_p256_mul_op_count_golden() {
    let ops = collect(|s| emit_p256_mul(s));
    // Rust emits 4 fewer raw StackOps than Python/Java peers; same pattern
    // as ecMul (see ec_codegen_tests.rs module comment). Final hex is
    // byte-identical (enforced by the conformance harness).
    assert_eq!(count_op_tree(&ops), 140616, "p256_mul op count drift");
}

#[test]
fn test_p256_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_p256_mul_gen(s));
    // See p256_mul_op_count_golden comment.
    assert_eq!(count_op_tree(&ops), 140618, "p256_mul_gen op count drift");
}

#[test]
fn test_p256_negate_op_count_golden() {
    let ops = collect(|s| emit_p256_negate(s));
    assert_eq!(count_op_tree(&ops), 956, "p256_negate op count drift");
}

#[test]
fn test_p256_on_curve_op_count_golden() {
    let ops = collect(|s| emit_p256_on_curve(s));
    assert_eq!(count_op_tree(&ops), 574, "p256_on_curve op count drift");
}

#[test]
fn test_p256_encode_compressed_op_count_golden() {
    let ops = collect(|s| emit_p256_encode_compressed(s));
    assert_eq!(count_op_tree(&ops), 16, "p256_encode_compressed op count drift");
}

#[test]
fn test_verify_ecdsa_p256_op_count_golden() {
    let ops = collect(|s| emit_verify_ecdsa_p256(s));
    // Rust emits 8 fewer raw StackOps than Python/Java peers (a verify
    // computes two mul/mul_gen invocations × the 4-op divergence).
    //
    // 297180 -> 297265 (+85 ops / +151 script bytes) for the `_dk_valid`
    // pubkey-validity gate, which decomposes as:
    //   * 52 curve-independent 1-byte ops — 21 for the affine-add P == -Q mask
    //     (see test_p256_add_op_count_golden), the rest for the residue +
    //     canonicity check in c_decompress_pub_key, its altstack stash, and the
    //     closing OP_BOOLAND in c_emit_verify_ecdsa. P-384 pays the same 52.
    //   * +1 op per set bit of the sqrt exponent — 33 here, 287 on P-384.
    //     `_dk_y2_keep` now sits under `_dk_y2` for the whole of c_field_pow, so
    //     the loop's copy_to_top(base) moves from depth 1 (OP_OVER) to depth 2
    //     (OP_2 + OP_PICK). (p+1)/4 has 34 set bits on P-256, 288 on P-384; the
    //     MSB is the loop's seed, not a step.
    //   * +66 bytes beyond the op count — the two full-width pushes of p the
    //     check adds (one in c_field_sqr's reduce, one for the OP_LESSTHAN):
    //     33 extra bytes each on P-256, 49 each on P-384.
    // 52 + 33 = 85 ops; 85 + 66 = 151 bytes. Both match the TS reference.
    //
    // 297265 -> 297323 (+58 ops / +225 script bytes) for the argument-validity
    // gates — the length clamp on `_sig` / `_pk`, the 1 <= r,s <= n-1 range gate
    // (a universal-forgery fix: an all-zero signature used to verify under any
    // key), and the SEC1 prefix test in c_decompress_pub_key. Decomposes as:
    //   * 23 ops / 124 bytes — the two length gates: 9 emitted ops each, plus
    //     the rot/roll bringing the two flags together and the OP_BOOLAND that
    //     joins them. Byte-heavy because each gate pushes `want` zero bytes
    //     (33 and 64 here) for the OP_CAT clamp.
    //   * 15 ops / 81 bytes — the range gate: OP_0NOTEQUAL, OP_LESSTHAN and
    //     OP_BOOLAND per scalar over a picked copy, plus the closing OP_BOOLAND.
    //     Two full-width pushes of n (34 bytes each on P-256) dominate.
    //   * 8 ops / 8 bytes — the prefix test; OP_2 / OP_3 are single-byte pushes.
    //   * 12 ops / 12 bytes — the two new AND chains (`_dk_curve_ok` ->
    //     `_dk_valid`, `_len_ok` -> `_arg_ok` -> `_input_ok`) and the rolls
    //     feeding them, including the extra OP_SWAP `_dk_pfx_ok` costs by
    //     sitting under `_dk_xbytes`. All 1-byte ops.
    // Every one of the 58 ops is curve-independent, so P-384 pays the same 58;
    // it pays 306 bytes rather than 225 purely on wider constants — +49 in the
    // length gates (49/96-byte pads) and +32 in the range gate (two 50-byte
    // pushes of n). Both totals match the TS reference.
    // R-053 / CL-BUG-096 — +50 more: verify_ecdsa_p256 calls c_affine_add
    // once, so it pays the infinity-operand select exactly once. See
    // test_p256_add_op_count_golden.
    assert_eq!(count_op_tree(&ops), 297385, "verify_ecdsa_p256 op count drift");
}

// -- P-384 -----------------------------------------------------------------

#[test]
fn test_p384_add_op_count_golden() {
    let ops = collect(|s| emit_p384_add(s));
    // 11448 -> 11469 (+21 ops / +21 bytes): same affine-add P == -Q -> O mask
    // as ecAdd / p256Add, see test_p256_add_op_count_golden.
    // R-053 / CL-BUG-096 — the infinity-operand select adds another +50 here.
    // It replaces the four px/py/qx/qy drops and the two standalone `notinf`
    // OP_MULs with the pinf/qinf/usep/useq/user mask chain plus the six OP_MUL
    // and four OP_ADD selects and the picks/rolls feeding them. Measured on
    // this tier's own baseline, not copied from TypeScript.
    // N-252, the y = 0 tangent guard: pNNNAdd +12 (three picks + OP_SWAP OP_NOT OP_BOOLAND OP_BOOLAND OP_NOT OP_VERIFY); verifyECDSA_* +0, it does not take the guard.
    assert_eq!(count_op_tree(&ops), 11555, "p384_add op count drift");
}

#[test]
fn test_p384_mul_op_count_golden() {
    let ops = collect(|s| emit_p384_mul(s));
    // See ec_codegen_tests.rs module comment for the 4-op divergence pattern.
    assert_eq!(count_op_tree(&ops), 211982, "p384_mul op count drift");
}

#[test]
fn test_p384_mul_gen_op_count_golden() {
    let ops = collect(|s| emit_p384_mul_gen(s));
    // See p384_mul_op_count_golden comment.
    assert_eq!(count_op_tree(&ops), 211984, "p384_mul_gen op count drift");
}

#[test]
fn test_p384_negate_op_count_golden() {
    let ops = collect(|s| emit_p384_negate(s));
    assert_eq!(count_op_tree(&ops), 1404, "p384_negate op count drift");
}
