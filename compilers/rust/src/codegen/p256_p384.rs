//! P-256 / P-384 codegen -- NIST elliptic curve operations for Bitcoin Script.
//!
//! Port of compilers/go/codegen/p256_p384.go.
//! Follows the same pattern as ec.rs (secp256k1), but with different field primes,
//! curve orders, and generator points.
//!
//! Point representation:
//!   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
//!   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
//!
//! Key difference from secp256k1: curve parameter a = -3 (not 0), which gives
//! an optimized Jacobian doubling formula.

use super::stack::{PushValue, StackOp};
use super::ec::emit_reverse_32;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::sync::LazyLock;

// ===========================================================================
// Big integer helpers
// ===========================================================================

fn bigint_from_hex(hex: &str) -> BigInt {
    BigInt::parse_bytes(hex.as_bytes(), 16).expect("invalid hex constant")
}

/// Convert a BigInt to N-byte big-endian representation.
fn bigint_to_n_bytes(n: &BigInt, size: usize) -> Vec<u8> {
    let (_, be_bytes) = n.to_bytes_be();
    let mut result = vec![0u8; size];
    let start = if be_bytes.len() > size { 0 } else { size - be_bytes.len() };
    let src_start = if be_bytes.len() > size { be_bytes.len() - size } else { 0 };
    result[start..].copy_from_slice(&be_bytes[src_start..]);
    result
}

/// Convert a BigInt to a Bitcoin script number (little-endian sign-magnitude).
fn bigint_to_script_num(n: &BigInt) -> Vec<u8> {
    if n.is_zero() {
        return vec![];
    }
    let (sign, be_bytes) = n.to_bytes_be();
    // Reverse to LE
    let mut le: Vec<u8> = be_bytes.into_iter().rev().collect();
    // If MSB has bit 7 set, append sign byte
    if *le.last().unwrap() & 0x80 != 0 {
        if sign == num_bigint::Sign::Minus {
            le.push(0x80);
        } else {
            le.push(0x00);
        }
    } else if sign == num_bigint::Sign::Minus {
        let last = le.last_mut().unwrap();
        *last |= 0x80;
    }
    le
}

// ===========================================================================
// P-256 constants (secp256r1 / NIST P-256)
// ===========================================================================

static P256_P: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));
static P256_P_MINUS_2: LazyLock<BigInt> = LazyLock::new(|| &*P256_P - 2);
static P256_B: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"));
static P256_N: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
static P256_N_MINUS_2: LazyLock<BigInt> = LazyLock::new(|| &*P256_N - 2);
static P256_GX: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
static P256_GY: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
static P256_SQRT_EXP: LazyLock<BigInt> = LazyLock::new(|| (&*P256_P + 1) >> 2);

// ===========================================================================
// P-384 constants (secp384r1 / NIST P-384)
// ===========================================================================

static P384_P: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"));
static P384_P_MINUS_2: LazyLock<BigInt> = LazyLock::new(|| &*P384_P - 2);
static P384_B: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"));
static P384_N: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"));
static P384_N_MINUS_2: LazyLock<BigInt> = LazyLock::new(|| &*P384_N - 2);
static P384_GX: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"));
static P384_GY: LazyLock<BigInt> = LazyLock::new(|| bigint_from_hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"));
static P384_SQRT_EXP: LazyLock<BigInt> = LazyLock::new(|| (&*P384_P + 1) >> 2);

// ===========================================================================
// Curve parameter structs
// ===========================================================================

struct NistCurveParams {
    field_p: &'static LazyLock<BigInt>,
    field_p_minus_2: &'static LazyLock<BigInt>,
    coord_bytes: usize, // 32 for P-256, 48 for P-384
    reverse_bytes: fn(&mut dyn FnMut(StackOp)),
}

struct NistGroupParams {
    n: &'static LazyLock<BigInt>,
    n_minus_2: &'static LazyLock<BigInt>,
}

static P256_CURVE: NistCurveParams = NistCurveParams {
    field_p: &P256_P,
    field_p_minus_2: &P256_P_MINUS_2,
    coord_bytes: 32,
    reverse_bytes: emit_reverse_32,
};

static P384_CURVE: NistCurveParams = NistCurveParams {
    field_p: &P384_P,
    field_p_minus_2: &P384_P_MINUS_2,
    coord_bytes: 48,
    reverse_bytes: emit_reverse_48,
};

static P256_GROUP: NistGroupParams = NistGroupParams {
    n: &P256_N,
    n_minus_2: &P256_N_MINUS_2,
};

static P384_GROUP: NistGroupParams = NistGroupParams {
    n: &P384_N,
    n_minus_2: &P384_N_MINUS_2,
};

// ===========================================================================
// Byte reversal for 48 bytes (P-384)
// ===========================================================================

fn emit_reverse_48(e: &mut dyn FnMut(StackOp)) {
    e(StackOp::Opcode("OP_0".into()));
    e(StackOp::Swap);
    for _ in 0..48 {
        e(StackOp::Push(PushValue::Int(BigInt::from(1))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Rot);
        e(StackOp::Rot);
        e(StackOp::Swap);
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Swap);
    }
    e(StackOp::Drop);
}

// ===========================================================================
// Collect ops helper
// ===========================================================================

fn collect_ops(f: impl FnOnce(&mut dyn FnMut(StackOp))) -> Vec<StackOp> {
    let mut ops = Vec::new();
    f(&mut |op| ops.push(op));
    ops
}

// The tracker is SHARED with ec.rs, not copied.
//
// It used to be duplicated here "since it's private there". That was tolerable
// while it was 200 lines of pure stack bookkeeping; it stopped being tolerable
// once it carried a sign lattice whose transfer functions decide which reduction
// shape gets emitted. Two independently-maintained copies of that is two chances
// to prove `Reduced` where only `NonNegative` holds — and the resulting script
// is smaller, passes every local test, and is wrong.
use super::ec::{comb_emit_select, Dom, ECTracker, EcCodegenOptions, POOL_FIELD_P, POOL_GROUP_N};
use super::comb::{comb_geometry, comb_safe_rounds, comb_table, CombCurve, P256_COMB_CURVE, P384_COMB_CURVE};
use super::cost_model::estimate_script_bytes;
use num_traits::ToPrimitive;

// ===========================================================================
// Generic curve field arithmetic (parameterized by prime)
// ===========================================================================

fn c_push_field_p(t: &mut ECTracker, name: &str, c: &NistCurveParams) {
    t.push_const(POOL_FIELD_P, &c.field_p, name);
}

/// `a mod p` with no sign fix-up: 1 opcode instead of 7. Sound only when the
/// dividend is provably >= 0 — the caller proves that, this does not check.
fn c_field_mod_short(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    c_push_field_p(t, "_fmods_p", c);
    t.raw_block(&[a_name, "_fmods_p"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_MOD".into()));
    });
    t.set_domain(result_name, Dom::Reduced);
}

/// Does the cheap `a - b + p` subtraction pay? Only when p is pooled.
fn c_cheap_sub_pays(t: &ECTracker, c: &NistCurveParams) -> bool {
    let cost = t.const_cost(POOL_FIELD_P, &c.field_p);
    2 * cost + 2 < cost + 8
}

fn c_field_mod(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
    if t.sinking && t.domain_of(a_name).is_non_negative() {
        c_field_mod_short(t, a_name, result_name, c);
        return;
    }
    t.to_top(a_name);
    c_push_field_p(t, "_fmod_p", c);
    t.raw_block(&[a_name, "_fmod_p"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_2DUP".into()));
        e(StackOp::Opcode("OP_MOD".into()));
        e(StackOp::Rot);
        e(StackOp::Drop);
        e(StackOp::Over);
        e(StackOp::Opcode("OP_ADD".into()));
        e(StackOp::Swap);
        e(StackOp::Opcode("OP_MOD".into()));
    });
    t.set_domain(result_name, Dom::Reduced);
}

fn c_field_add(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    // Read the operand facts before raw_block consumes their slots.
    let sum_non_neg =
        t.domain_of(a_name).is_non_negative() && t.domain_of(b_name).is_non_negative();
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fadd_sum"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    if sum_non_neg {
        t.set_domain("_fadd_sum", Dom::NonNegative);
    }
    c_field_mod(t, "_fadd_sum", result_name, c);
}

fn c_field_sub(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    t.to_top(b_name);
    // Needs a >= 0 AND b in [0, p): then a - b > -p and one shifted reduction is
    // exact. `b >= 0` alone is not enough — a coordinate decoded from 32 unsigned
    // bytes may exceed p by up to 2^32 + 977.
    let cheap = t.sinking
        && t.domain_of(a_name).is_non_negative()
        && t.domain_of(b_name) == Dom::Reduced
        && c_cheap_sub_pays(t, c);

    t.raw_block(&[a_name, b_name], Some("_fsub_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });

    if cheap {
        c_push_field_p(t, "_fsub_p", c);
        t.raw_block(&["_fsub_diff", "_fsub_p"], Some("_fsub_shift"), |e| {
            e(StackOp::Opcode("OP_ADD".into()));
        });
        t.set_domain("_fsub_shift", Dom::NonNegative);
        c_field_mod_short(t, "_fsub_shift", result_name, c);
        return;
    }
    c_field_mod(t, "_fsub_diff", result_name, c);
}

fn c_field_mul(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    c_field_mul_signed(t, a_name, b_name, result_name, c, false);
}

/// `c_field_mul` with an explicit assertion about the product's sign,
/// independent of the operands: a*a >= 0 for any a whatsoever.
fn c_field_mul_signed(
    t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams,
    product_non_negative: bool,
) {
    let non_neg = product_non_negative
        || (t.domain_of(a_name).is_non_negative() && t.domain_of(b_name).is_non_negative());
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fmul_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    if non_neg {
        t.set_domain("_fmul_prod", Dom::NonNegative);
    }
    c_field_mod(t, "_fmul_prod", result_name, c);
}

fn c_field_mul_const(t: &mut ECTracker, a_name: &str, cv: i128, result_name: &str, c: &NistCurveParams) {
    // Every call site passes a small positive cv, so the product keeps a's sign.
    let non_neg = cv > 0 && t.domain_of(a_name).is_non_negative();
    t.to_top(a_name);
    t.raw_block(&[a_name], Some("_fmc_prod"), |e| {
        if cv == 2 {
            e(StackOp::Opcode("OP_2MUL".into()));
        } else {
            e(StackOp::Push(PushValue::Int(BigInt::from(cv))));
            e(StackOp::Opcode("OP_MUL".into()));
        }
    });
    if non_neg {
        t.set_domain("_fmc_prod", Dom::NonNegative);
    }
    c_field_mod(t, "_fmc_prod", result_name, c);
}

fn c_field_sqr(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
    t.copy_to_top(a_name, "_fsqr_copy");
    c_field_mul_signed(t, a_name, "_fsqr_copy", result_name, c, true);
}

/// c_field_inv computes a^(p-2) mod p via generic square-and-multiply.
fn c_field_inv(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
    let exp = &**c.field_p_minus_2;
    let bits = exp.bits() as usize;

    // Start: result = a (highest bit of exp is 1)
    t.copy_to_top(a_name, "_inv_r");

    for i in (0..bits - 1).rev() {
        c_field_sqr(t, "_inv_r", "_inv_r2", c);
        t.rename("_inv_r");
        if exp.bit(i as u64) {
            t.copy_to_top(a_name, "_inv_a");
            c_field_mul(t, "_inv_r", "_inv_a", "_inv_m", c);
            t.rename("_inv_r");
        }
    }

    t.to_top(a_name);
    t.drop();
    t.to_top("_inv_r");
    t.rename(result_name);
}

// ===========================================================================
// Group-order arithmetic (for ECDSA: mod n operations)
// ===========================================================================

fn c_push_group_n(t: &mut ECTracker, name: &str, g: &NistGroupParams) {
    t.push_const(POOL_GROUP_N, &g.n, name);
}

fn c_group_mod(t: &mut ECTracker, a_name: &str, result_name: &str, g: &NistGroupParams) {
    t.to_top(a_name);
    c_push_group_n(t, "_gmod_n", g);
    t.raw_block(&[a_name, "_gmod_n"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_2DUP".into()));
        e(StackOp::Opcode("OP_MOD".into()));
        e(StackOp::Rot);
        e(StackOp::Drop);
        e(StackOp::Over);
        e(StackOp::Opcode("OP_ADD".into()));
        e(StackOp::Swap);
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

/// Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
///
/// OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
/// the `+ n, mod n` normalises the negative half. One push of n covers both
/// reductions — the same shape as `emit_ec_mod_reduce`.
///
/// Without it, `c_emit_mul`'s ladder is only correct while
/// 2^b <= k + 3n < 2^(b+1) for the fixed b it unrolls: a scalar >= ~n sets a bit
/// above the loop's top, the loop never sees it, and the ladder returns a
/// DIFFERENT multiple of P rather than failing. Scalars are contract input, so
/// that is attacker-chosen. Reducing costs 1 push + 8 opcodes (42 / 58 bytes)
/// against a ~460 KB / 1.6 MB script, and makes k >= n, k < 0 and k = 0 all
/// well defined.
fn c_emit_scalar_reduce(t: &mut ECTracker, k_name: &str, result_name: &str, g: &NistGroupParams) {
    c_push_group_n(t, "_n_red", g);
    t.raw_block(&[k_name, "_n_red"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_2DUP".into()));
        e(StackOp::Opcode("OP_MOD".into()));
        e(StackOp::Rot);
        e(StackOp::Drop);
        e(StackOp::Over);
        e(StackOp::Opcode("OP_ADD".into()));
        e(StackOp::Swap);
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

fn c_group_mul(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, g: &NistGroupParams) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_gmul_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    c_group_mod(t, "_gmul_prod", result_name, g);
}

/// c_group_inv computes a^(n-2) mod n via square-and-multiply.
fn c_group_inv(t: &mut ECTracker, a_name: &str, result_name: &str, g: &NistGroupParams) {
    let exp = &**g.n_minus_2;
    let bits = exp.bits() as usize;

    t.copy_to_top(a_name, "_ginv_r");

    for i in (0..bits - 1).rev() {
        // Square
        t.copy_to_top("_ginv_r", "_ginv_sq_copy");
        c_group_mul(t, "_ginv_r", "_ginv_sq_copy", "_ginv_sq", g);
        t.rename("_ginv_r");
        if exp.bit(i as u64) {
            t.copy_to_top(a_name, "_ginv_a");
            c_group_mul(t, "_ginv_r", "_ginv_a", "_ginv_m", g);
            t.rename("_ginv_r");
        }
    }

    t.to_top(a_name);
    t.drop();
    t.to_top("_ginv_r");
    t.rename(result_name);
}

// ===========================================================================
// Point decompose / compose (parameterized by coordinate byte size)
// ===========================================================================

fn c_decompose_point(t: &mut ECTracker, point_name: &str, x_name: &str, y_name: &str, c: &NistCurveParams) {
    t.to_top(point_name);
    t.raw_block(&[point_name], None, |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(c.coord_bytes as i128))));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.push_tracked("_dp_xb", Dom::Unknown);
    t.push_tracked("_dp_yb", Dom::Unknown);

    // Convert y_bytes (on top) to num
    t.raw_block(&["_dp_yb"], Some(y_name), |e| {
        (c.reverse_bytes)(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });
    // A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    // UNSIGNED: >= 0, but it may be up to 2^(8*coord_bytes) - 1 and therefore
    // >= p. That gap is exactly what the subtraction precondition turns on.
    t.set_domain(y_name, Dom::NonNegative);

    // Convert x_bytes to num
    t.to_top("_dp_xb");
    t.raw_block(&["_dp_xb"], Some(x_name), |e| {
        (c.reverse_bytes)(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });
    t.set_domain(x_name, Dom::NonNegative);

    // Swap to standard order [xName, yName]
    t.swap();
}

fn c_compose_point(t: &mut ECTracker, x_name: &str, y_name: &str, result_name: &str, c: &NistCurveParams) {
    let num_bin_size = (c.coord_bytes + 1) as i128;

    // Convert x to coordBytes big-endian
    t.to_top(x_name);
    let rev_fn = c.reverse_bytes;
    let cb = c.coord_bytes as i128;
    t.raw_block(&[x_name], Some("_cp_xb"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(num_bin_size))));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(cb))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        rev_fn(e);
    });

    // Convert y to coordBytes big-endian
    t.to_top(y_name);
    t.raw_block(&[y_name], Some("_cp_yb"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(num_bin_size))));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(cb))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        rev_fn(e);
    });

    // Cat: x_be || y_be
    t.to_top("_cp_xb");
    t.to_top("_cp_yb");
    t.raw_block(&["_cp_xb", "_cp_yb"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_CAT".into()));
    });
}

// ===========================================================================
// Affine point addition
// ===========================================================================

/// GAP-301: coordinate canonicity, leaving `_canon` on the tracker.
///
/// `c_decompose_point` BIN2NUMs each coordinate as an unsigned value that may
/// be >= p; the curve equation reduces it mod p, so (x + p)||y would pass as a
/// point it is not the canonical encoding of. Reject it: require x < p AND
/// y < p (coordinates are unsigned, so the 0 <= bound holds by construction).
/// The caller ANDs `_canon` into its result so the check still returns a
/// boolean. This mirrors secp256k1's `emit_ec_on_curve`, whose guard the a = -3
/// curves never received — leaving `pNNNOnCurve` accepting inputs `ecOnCurve`
/// rejects even though both are documented as THE gate for untrusted points.
fn c_emit_canonicity_guard(t: &mut ECTracker, x_name: &str, y_name: &str, c: &NistCurveParams) {
    t.copy_to_top(x_name, "_x_lt");
    c_push_field_p(t, "_p_for_x", c);
    t.raw_block(&["_x_lt", "_p_for_x"], Some("_x_canon"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.copy_to_top(y_name, "_y_lt");
    c_push_field_p(t, "_p_for_y", c);
    t.raw_block(&["_y_lt", "_p_for_y"], Some("_y_canon"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.to_top("_x_canon");
    t.to_top("_y_canon");
    t.raw_block(&["_x_canon", "_y_canon"], Some("_canon"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
}

fn c_affine_add(t: &mut ECTracker, c: &NistCurveParams) {
    // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
    // denominator is zero and the correct slope is the TANGENT,
    // (3px^2 + a)/(2py) — and a = -3 on both NIST curves, so the numerator is
    // 3px^2 - 3. The secp256k1 fix (a = 0) was never ported here, so
    // p256Add(P, P) and p384Add(P, P) produced a wrong point and every contract
    // that doubled deployed an unspendable script.
    //
    // Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR are
    // selected and the single expensive c_field_inv still runs exactly once.
    // rx and ry below are already correct for doubling.
    //
    //   cond = (px == qx) AND (py == qy)
    //   num  = cond ? 3*px^2 - 3 : (qy - py)
    //   den  = cond ? 2*py       : (qx - px)
    //
    // selected as `b + cond*(a - b)`, which needs no branch and keeps the
    // emitted op sequence identical on both paths.
    //
    // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
    // sends it down the tangent path and returns 2P — an on-curve, entirely
    // plausible, WRONG point, which is strictly worse than the pre-fix chord
    // path: that one divided by zero (c_field_inv is Fermat, inv(0) = 0) and
    // produced an OFF-curve blob, so `assert(pNNNOnCurve(pNNNAdd(a, b)))` — the
    // idiom examples/ts/p384-primitives writes verbatim — rejected it.
    //
    // P + (-P) is the point at infinity, which affine x||y cannot represent.
    // This codegen already has a representation for O: the ALL-ZERO blob, which
    // is what `pNNNMul(P, 0n)` returns. So return that, by masking the result
    // with `notinf = NOT(px == qx AND NOT cond)`. O is not on the curve
    // (0^2 != b), so the on-curve gate rejects it and the idiom works again;
    // and it adds no failure channel to a pure value-producing expression, the
    // same reason c_emit_scalar_reduce reduces instead of rejecting.
    //
    // The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
    // and notinf is 0 or 1, so the product is canonical either way.
    t.copy_to_top("px", "_px_eq");
    t.copy_to_top("qx", "_qx_eq");
    t.raw_block(&["_px_eq", "_qx_eq"], Some("_xeq"), |e| {
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
    });
    t.copy_to_top("py", "_py_eq");
    t.copy_to_top("qy", "_qy_eq");
    t.raw_block(&["_py_eq", "_qy_eq"], Some("_yeq"), |e| {
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
    });
    t.copy_to_top("_xeq", "_xeq_c");
    t.to_top("_yeq");
    t.raw_block(&["_xeq_c", "_yeq"], Some("_cond"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    // notinf = NOT(xeq - cond): 1 exactly when px == qx and the points differ.
    t.to_top("_xeq");
    t.copy_to_top("_cond", "_cond_c");
    t.raw_block(&["_xeq", "_cond_c"], Some("_notinf"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
        e(StackOp::Opcode("OP_NOT".into()));
    });

    // chord numerator / denominator
    t.copy_to_top("qy", "_qy1");
    t.copy_to_top("py", "_py1");
    c_field_sub(t, "_qy1", "_py1", "_num_chord", c);
    t.copy_to_top("qx", "_qx1");
    t.copy_to_top("px", "_px1");
    c_field_sub(t, "_qx1", "_px1", "_den_chord", c);

    // tangent numerator / denominator: 3*px^2 + a (a = -3) and 2*py
    t.copy_to_top("px", "_px_t");
    c_field_sqr(t, "_px_t", "_px_sq", c);
    c_field_mul_const(t, "_px_sq", 3, "_3px_sq", c);
    t.push_int("_a_neg", 3);
    c_field_sub(t, "_3px_sq", "_a_neg", "_num_tan", c);
    t.copy_to_top("py", "_py_t");
    c_field_mul_const(t, "_py_t", 2, "_den_tan", c);

    // num = num_chord + cond*(num_tan - num_chord)
    t.copy_to_top("_num_chord", "_num_chord_c");
    c_field_sub(t, "_num_tan", "_num_chord_c", "_num_diff", c);
    t.copy_to_top("_cond", "_cond_n");
    c_field_mul(t, "_num_diff", "_cond_n", "_num_sel", c);
    c_field_add(t, "_num_chord", "_num_sel", "_s_num", c);

    // den = den_chord + cond*(den_tan - den_chord)
    t.copy_to_top("_den_chord", "_den_chord_c");
    c_field_sub(t, "_den_tan", "_den_chord_c", "_den_diff", c);
    t.to_top("_cond");
    t.rename("_cond_d");
    c_field_mul(t, "_den_diff", "_cond_d", "_den_sel", c);
    c_field_add(t, "_den_chord", "_den_sel", "_s_den", c);

    // s = s_num / s_den mod p
    c_field_inv(t, "_s_den", "_s_den_inv", c);
    c_field_mul(t, "_s_num", "_s_den_inv", "_s", c);

    // rx = s^2 - px - qx mod p
    t.copy_to_top("_s", "_s_keep");
    c_field_sqr(t, "_s", "_s2", c);
    t.copy_to_top("px", "_px2");
    c_field_sub(t, "_s2", "_px2", "_rx1", c);
    t.copy_to_top("qx", "_qx2");
    c_field_sub(t, "_rx1", "_qx2", "rx", c);

    // ry = s * (px - rx) - py mod p
    t.copy_to_top("px", "_px3");
    t.copy_to_top("rx", "_rx2");
    c_field_sub(t, "_px3", "_rx2", "_px_rx", c);
    c_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx", c);
    t.copy_to_top("py", "_py2");
    c_field_sub(t, "_s_px_rx", "_py2", "ry", c);

    // Clean up original points
    t.to_top("px"); t.drop();
    t.to_top("py"); t.drop();
    t.to_top("qx"); t.drop();
    t.to_top("qy"); t.drop();

    // P == -Q -> force the all-zero point (see the header comment).
    t.to_top("rx");
    t.copy_to_top("_notinf", "_notinf_x");
    t.raw_block(&["rx", "_notinf_x"], Some("rx"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    t.to_top("ry");
    t.to_top("_notinf");
    t.raw_block(&["ry", "_notinf"], Some("ry"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
}

// ===========================================================================
// Jacobian point doubling with a=-3 optimization
// ===========================================================================

fn c_jacobian_double(t: &mut ECTracker, c: &NistCurveParams) {
    // Z^2
    t.copy_to_top("jz", "_jz_sq_tmp");
    c_field_sqr(t, "_jz_sq_tmp", "_Z2", c);

    // X - Z^2 and X + Z^2
    t.copy_to_top("jx", "_jx_c1");
    t.copy_to_top("_Z2", "_Z2_c1");
    c_field_sub(t, "_jx_c1", "_Z2_c1", "_X_minus_Z2", c);
    t.copy_to_top("jx", "_jx_c2");
    c_field_add(t, "_jx_c2", "_Z2", "_X_plus_Z2", c);

    // A = 3*(X-Z^2)*(X+Z^2)
    c_field_mul(t, "_X_minus_Z2", "_X_plus_Z2", "_prod", c);
    t.push_int("_three", 3);
    c_field_mul(t, "_prod", "_three", "_A", c);

    // B = 4*X*Y^2
    t.copy_to_top("jy", "_jy_sq_tmp");
    c_field_sqr(t, "_jy_sq_tmp", "_Y2", c);
    t.copy_to_top("_Y2", "_Y2_c1");
    t.copy_to_top("jx", "_jx_c3");
    c_field_mul(t, "_jx_c3", "_Y2", "_xY2", c);
    t.push_int("_four", 4);
    c_field_mul(t, "_xY2", "_four", "_B", c);

    // C = 8*Y^4
    c_field_sqr(t, "_Y2_c1", "_Y4", c);
    t.push_int("_eight", 8);
    c_field_mul(t, "_Y4", "_eight", "_C", c);

    // X3 = A^2 - 2*B
    t.copy_to_top("_A", "_A_save");
    t.copy_to_top("_B", "_B_save");
    c_field_sqr(t, "_A", "_A2", c);
    t.copy_to_top("_B", "_B_c1");
    c_field_mul_const(t, "_B_c1", 2, "_2B", c);
    c_field_sub(t, "_A2", "_2B", "_X3", c);

    // Y3 = A*(B - X3) - C
    t.copy_to_top("_X3", "_X3_c");
    c_field_sub(t, "_B_save", "_X3_c", "_B_minus_X3", c);
    c_field_mul(t, "_A_save", "_B_minus_X3", "_A_tmp", c);
    c_field_sub(t, "_A_tmp", "_C", "_Y3", c);

    // Z3 = 2*Y*Z
    t.copy_to_top("jy", "_jy_c");
    t.copy_to_top("jz", "_jz_c");
    c_field_mul(t, "_jy_c", "_jz_c", "_yz", c);
    c_field_mul_const(t, "_yz", 2, "_Z3", c);

    // Clean up and rename
    t.to_top("_B"); t.drop();
    t.to_top("jz"); t.drop();
    t.to_top("jx"); t.drop();
    t.to_top("jy"); t.drop();
    t.to_top("_X3"); t.rename("jx");
    t.to_top("_Y3"); t.rename("jy");
    t.to_top("_Z3"); t.rename("jz");
}

// ===========================================================================
// Jacobian to affine conversion
// ===========================================================================

fn c_jacobian_to_affine(t: &mut ECTracker, rx_name: &str, ry_name: &str, c: &NistCurveParams) {
    c_field_inv(t, "jz", "_zinv", c);
    t.copy_to_top("_zinv", "_zinv_keep");
    c_field_sqr(t, "_zinv", "_zinv2", c);
    t.copy_to_top("_zinv2", "_zinv2_keep");
    c_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3", c);
    c_field_mul(t, "jx", "_zinv2_keep", rx_name, c);
    c_field_mul(t, "jy", "_zinv3", ry_name, c);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

fn c_build_jacobian_add_affine_inline(e: &mut dyn FnMut(StackOp), t: &ECTracker, c: &NistCurveParams) {
    let cloned_nm: Vec<String> = t.nm.clone();
    let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
    let opts = t.options();
    let mut it = ECTracker::with_opts(&init_strs, e, Some(&opts), Some(&t.dm));
    c_jacobian_add_affine_body(&mut it, false, c);
}

/// The mixed-add itself, emitting through an ECTracker the caller owns.
///
/// `keep_hr` additionally leaves copies of H and R on the stack: both are zero
/// exactly when the Jacobian accumulator is the same curve point as the affine
/// operand, the one case these formulas cannot compute. See
/// `c_build_jacobian_add_or_double_inline`.
fn c_jacobian_add_affine_body(it: &mut ECTracker, keep_hr: bool, c: &NistCurveParams) {
    it.copy_to_top("jz", "_jz_for_z1cu");
    it.copy_to_top("jz", "_jz_for_z3");
    it.copy_to_top("jy", "_jy_for_y3");
    it.copy_to_top("jx", "_jx_for_u1h2");

    // Z1sq = jz^2
    c_field_sqr(it, "jz", "_Z1sq", c);

    // Z1cu = _jz_for_z1cu * Z1sq
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2");
    c_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", c);

    // U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c");
    c_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2", c);

    // S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c");
    c_field_mul(it, "_ay_c", "_Z1cu", "_S2", c);

    // H = U2 - jx
    c_field_sub(it, "_U2", "jx", "_H", c);

    // R = S2 - jy
    c_field_sub(it, "_S2", "jy", "_R", c);

    if keep_hr {
        it.copy_to_top("_H", "_H_keep");
        it.copy_to_top("_R", "_R_keep");
    }

    it.copy_to_top("_H", "_H_for_h3");
    it.copy_to_top("_H", "_H_for_z3");

    // H2 = H^2
    c_field_sqr(it, "_H", "_H2", c);

    it.copy_to_top("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    c_field_mul(it, "_H_for_h3", "_H2", "_H3", c);

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    c_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", c);

    it.copy_to_top("_R", "_R_for_y3");
    it.copy_to_top("_U1H2", "_U1H2_for_y3");
    it.copy_to_top("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    c_field_sqr(it, "_R", "_R2", c);
    c_field_sub(it, "_R2", "_H3", "_x3_tmp", c);
    c_field_mul_const(it, "_U1H2", 2, "_2U1H2", c);
    c_field_sub(it, "_x3_tmp", "_2U1H2", "_X3", c);

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c");
    c_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", c);
    c_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp", c);
    c_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", c);
    c_field_sub(it, "_r_tmp", "_jy_h3", "_Y3", c);

    // Z3 = _jz_for_z3 * _H_for_z3
    c_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3", c);

    it.to_top("_X3"); it.rename("jx");
    it.to_top("_Y3"); it.rename("jy");
    it.to_top("_Z3"); it.rename("jz");
}

/// Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
/// Consumes `add_name`, `dbl_name` and `cond_name`.
fn c_select_coord(
    t: &mut ECTracker, add_name: &str, dbl_name: &str, cond_name: &str, result_name: &str,
    c: &NistCurveParams,
) {
    t.copy_to_top(add_name, "_sel_add_c");
    c_field_sub(t, dbl_name, "_sel_add_c", "_sel_diff", c);
    c_field_mul(t, "_sel_diff", cond_name, "_sel_scaled", c);
    c_field_add(t, add_name, "_sel_scaled", result_name, c);
}

/// The ladder's LAST conditional step: mixed-add, but correct when the
/// accumulator already equals the point being added.
///
/// The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
/// two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
/// infinity — and since `c_field_inv` is Fermat (inv(0) = 0),
/// `c_jacobian_to_affine` turns that into the ALL-ZERO point instead of 2P.
/// `p256Mul(P, 2n)` and `p384Mul(P, 2n)` returned 64 / 96 zero bytes.
///
/// WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
/// c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
/// (c_i - 1)*P. P-256 and P-384 both have cofactor 1, so P has order n and the
/// degenerate cases are exactly c_i ≡ 2 (mod n) — accumulator == P — and
/// c_i ≡ 0 or 1 (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS
/// interval determined only by i, so this is decidable by interval arithmetic
/// rather than by sampling, and over the whole domain k ∈ [0, n-1] only two
/// steps qualify, both at i = 0:
///
///   k = 2  ->  c_0 = 3n+2 ≡ 2, odd, so the add runs: accumulator == P.  <- bug
///   k = 0  ->  c_0 = 3n   ≡ 0, odd, so the add runs: accumulator == -P,
///              true result the point at infinity, which affine coordinates
///              cannot represent; it stays the all-zero point, as before.
///
/// At i ≥ 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
/// because the reduce puts k = 0 in the domain.
///
/// Handling H == 0 at every step would cost ~75% more script bytes — on P-384
/// that is another 600 KB; handling it here costs ~0.2%. The operand P is
/// caller-supplied but cannot move the exception, because the condition depends
/// only on c_i mod ord(P) and ord(P) = n for every point on these curves.
/// Points that are NOT on the curve carry no such guarantee — gate untrusted
/// input on `p256OnCurve` / `p384OnCurve` first. `c_decompress_pub_key` now
/// enforces that itself for the one in-tree caller that takes a pubkey as
/// input.
///
/// THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
/// because `c_emit_mul` reduces k mod n before adding 3n. That reduce landed
/// one commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN
/// IS UNSOUND: a last-step-only select while the scalar is still unbounded
/// leaves c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits
/// must land together and must never be bisected, cherry-picked or reverted
/// apart.
///
/// The interval argument does 100% of the work; there is no defence in depth
/// here. In particular c_i ≡ 1 (mod n) — a pre-add accumulator of O — is
/// UNREACHABLE, not handled: were it reachable the select would still take the
/// ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
/// H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
/// the reduce must redo the interval check, not assume this still holds.
///
/// Stack layout: [..., ax, ay, _k, jx, jy, jz] — same in and out.
fn c_build_jacobian_add_or_double_inline(
    e: &mut dyn FnMut(StackOp), t: &ECTracker, c: &NistCurveParams,
) {
    let cloned_nm: Vec<String> = t.nm.clone();
    let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
    let opts = t.options();
    let mut it = ECTracker::with_opts(&init_strs, e, Some(&opts), Some(&t.dm));
    let it = &mut it;

    // Keep the pre-add accumulator: it is what must be DOUBLED in the
    // exceptional case, and the add below consumes jx/jy/jz.
    it.copy_to_top("jx", "_sx");
    it.copy_to_top("jy", "_sy");
    it.copy_to_top("jz", "_sz");

    c_jacobian_add_affine_body(it, true, c);

    // cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
    // accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
    // signals the point at infinity.
    it.to_top("_H_keep");
    it.push_int("_zero_h", 0);
    it.raw_block(&["_H_keep", "_zero_h"], Some("_h_is0"), |e2| {
        e2(StackOp::Opcode("OP_NUMEQUAL".into()));
    });
    it.to_top("_R_keep");
    it.push_int("_zero_r", 0);
    it.raw_block(&["_R_keep", "_zero_r"], Some("_r_is0"), |e2| {
        e2(StackOp::Opcode("OP_NUMEQUAL".into()));
    });
    it.to_top("_h_is0");
    it.to_top("_r_is0");
    it.raw_block(&["_h_is0", "_r_is0"], Some("_cond"), |e2| {
        e2(StackOp::Opcode("OP_BOOLAND".into()));
    });

    // Move the add result aside so c_jacobian_double can work on jx/jy/jz
    // again, this time holding the saved accumulator.
    it.to_top("jx"); it.rename("_add_x");
    it.to_top("jy"); it.rename("_add_y");
    it.to_top("jz"); it.rename("_add_z");
    it.to_top("_sx"); it.rename("jx");
    it.to_top("_sy"); it.rename("jy");
    it.to_top("_sz"); it.rename("jz");
    c_jacobian_double(it, c);
    it.to_top("jx"); it.rename("_dbl_x");
    it.to_top("jy"); it.rename("_dbl_y");
    it.to_top("jz"); it.rename("_dbl_z");

    it.copy_to_top("_cond", "_cond_x");
    c_select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx", c);
    it.copy_to_top("_cond", "_cond_y");
    c_select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy", c);
    it.to_top("_cond"); it.rename("_cond_z");
    c_select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz", c);
}

// ===========================================================================
// Scalar multiplication (generic for both P-256 and P-384)
// ===========================================================================

fn c_emit_mul(
    emit: &mut dyn FnMut(StackOp),
    c: &NistCurveParams,
    g: &NistGroupParams,
    opts: Option<&EcCodegenOptions>,
) {
    let mut t = ECTracker::with_opts(&["_pt", "_k"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &c.field_p);
    t.pool_constant(POOL_GROUP_N, &g.n);
    c_decompose_point(&mut t, "_pt", "ax", "ay", c);

    // k' = k + 3n, as THREE separate `+n` steps.
    //
    // This tier used to push a pre-folded `3n` "to match Go peephole optimizer
    // output". Emitting the three steps is what the reference does, and the
    // peephole's fold-chain-add collapses them back to the same `push 3n, ADD`
    // — so the shipped bytes are unchanged while the pre-peephole form now
    // matches the reference exactly, which is what the cross-tier flag-parity
    // fixture compares.
    //
    // The "k ∈ [1, n-1]" precondition is one the caller cannot enforce — the
    // scalar is usually an unlock argument — so reduce it first.
    t.to_top("_k");
    c_emit_scalar_reduce(&mut t, "_k", "_kr", g);
    // These three route through the POOL, matching the secp256k1 twin.
    // They used to be raw literal pushes, which made the poolConstant of the
    // group order above a strict LOSS: the slot was redeemed exactly once, by
    // cEmitScalarReduce, so under --ec-constant-pool P-256 paid park 34 +
    // pick 2 + release 2-3 = 38-39 bytes where a bare literal costs 34.
    // Break-even is two redemptions; this is now four.
    t.push_const(POOL_GROUP_N, &g.n, "_n");
    t.raw_block(&["_kr", "_n"], Some("_kn"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_const(POOL_GROUP_N, &g.n, "_n2");
    t.raw_block(&["_kn", "_n2"], Some("_kn2"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_const(POOL_GROUP_N, &g.n, "_n3");
    t.raw_block(&["_kn2", "_n3"], Some("_kn3"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.rename("_k");

    // Determine iteration count based on 3*n bit length
    let four_n_minus_1: BigInt = (&**g.n) * 4 - BigInt::one();
    let top_bit = four_n_minus_1.bits() as usize;
    let start_bit = top_bit - 2; // highest bit is always 1 (init), start from next

    // Init accumulator = P (top bit of k+3n is always 1)
    t.copy_to_top("ax", "jx");
    t.copy_to_top("ay", "jy");
    t.push_int("jz", 1);

    // Iterate from start_bit down to 0
    for bit in (0..=start_bit).rev() {
        c_jacobian_double(&mut t, c);

        // Extract bit: (k >> bit) & 1
        t.copy_to_top("_k", "_k_copy");
        if bit == 1 {
            t.raw_block(&["_k_copy"], Some("_shifted"), |e| {
                e(StackOp::Opcode("OP_2DIV".into()));
            });
        } else if bit > 1 {
            t.push_int("_shift", bit as i128);
            t.raw_block(&["_k_copy", "_shift"], Some("_shifted"), |e| {
                e(StackOp::Opcode("OP_RSHIFTNUM".into()));
            });
        } else {
            t.rename("_shifted");
        }
        t.push_int("_two", 2);
        t.raw_block(&["_shifted", "_two"], Some("_bit"), |e| {
            e(StackOp::Opcode("OP_MOD".into()));
        });

        // Conditional add
        t.to_top("_bit");
        t.pop_tracked(); // _bit consumed by IF
        // Only the final step can be handed two equal operands — see
        // c_build_jacobian_add_or_double_inline for why, and for what it costs
        // not to.
        let add_ops = collect_ops(|add_emit| {
            if bit == 0 {
                c_build_jacobian_add_or_double_inline(add_emit, &t, c);
            } else {
                c_build_jacobian_add_affine_inline(add_emit, &t, c);
            }
        });
        (t.e)(StackOp::If {
            then_ops: add_ops,
            else_ops: vec![],
        });
    }

    c_jacobian_to_affine(&mut t, "_rx", "_ry", c);

    // Clean up
    t.to_top("ax"); t.drop();
    t.to_top("ay"); t.drop();
    t.to_top("_k"); t.drop();

    c_compose_point(&mut t, "_rx", "_ry", "_result", c);
    t.release_constant(POOL_GROUP_N);
    t.release_constant(POOL_FIELD_P);
}


// ===========================================================================
// Fixed-base comb (the base is a compile-time constant)
// ===========================================================================

/// `k·G` by a Lim-Lee comb, for a base known at compile time.
///
/// The binary ladder runs one doubling and one conditional add per scalar BIT. A
/// comb splits the scalar into `w` blocks of `d` bits and runs one doubling and
/// one conditional add per COLUMN, so the round count falls from `w*d` to `d` at
/// the price of a `2^w - 1` entry table — which costs nothing to build here,
/// because `G` is a constant. Measured optimum is w=3: the selection logic grows
/// as `2^w` and overtakes the saving by w=5.
///
/// SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
/// accumulator equal to the addend, its negation, or the point at infinity.
/// `c_build_jacobian_add_or_double_inline`'s comment justifies using it
/// everywhere but the last step of the BINARY ladder by an interval argument
/// over `c_i mod n`, and insists that argument be re-derived by anything
/// changing the offset or the iteration count. A comb changes both, so it is
/// re-derived — as executable interval arithmetic in `comb_safe_rounds`,
/// evaluated here. Rounds it cannot prove get the complete add-or-double form
/// instead; nothing is assumed. For P-256 at w=3 it proves 81 of 86 rounds.
///
/// The other half of that argument is that the accumulator never starts at
/// infinity, which needs the first digit non-zero. `comb_geometry` searches for
/// the scalar offset that guarantees it rather than reusing the ladder's
/// hardcoded `+3n` — which happens to be right for P-256 at w=3 and WRONG for
/// P-384.
///
/// Stack in: [_k]. Stack out: [_result]. Returns false when no geometry exists.
fn c_emit_comb_mul_gen(
    emit: &mut dyn FnMut(StackOp),
    c: &NistCurveParams,
    g: &NistGroupParams,
    curve: &CombCurve,
    w: usize,
    opts: Option<&EcCodegenOptions>,
) -> bool {
    let params = match comb_geometry(w, curve) {
        Some(p) => p,
        None => return false,
    };
    let d = params.d;
    let table = comb_table(w, d, curve);
    let safe = comb_safe_rounds(&params, curve);
    let entries = (1usize << w) - 1;

    let mut t = ECTracker::with_opts(&["_k"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &c.field_p);
    t.pool_constant(POOL_GROUP_N, &g.n);

    // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
    // what makes the interval argument apply at all; see `c_emit_scalar_reduce`.
    t.to_top("_k");
    c_emit_scalar_reduce(&mut t, "_k", "_kr", g);
    t.rename("_k");
    let offset = params.offset_multiple.to_u32().expect("comb offset fits u32");
    for i in 0..offset {
        let off = format!("_off{}", i);
        t.push_const(POOL_GROUP_N, &g.n, &off);
        t.raw_block(&["_k", &off], Some("_k"), |e| {
            e(StackOp::Opcode("OP_ADD".into()));
        });
    }
    t.set_domain("_k", Dom::NonNegative);

    // Table, resident for the whole comb: picking an entry costs 2-3 bytes
    // against a 34-byte literal push, and every round reads all of them.
    for j in 1..=entries {
        let pt = table[j].as_ref().expect("comb table entry is never infinity");
        t.push_big(&format!("_Tx{}", j), &pt.x);
        t.push_big(&format!("_Ty{}", j), &pt.y);
        t.set_domain(&format!("_Tx{}", j), Dom::Reduced);
        t.set_domain(&format!("_Ty{}", j), Dom::Reduced);
    }

    // Round d-1 initialises the accumulator. The first digit is non-zero by
    // construction (`comb_geometry`), so this is a real point, never infinity.
    comb_emit_select(&mut t, d - 1, w, d);
    t.to_top("_flag");
    t.drop();
    t.to_top("ax");
    t.rename("jx");
    t.to_top("ay");
    t.rename("jy");
    t.push_int("jz", 1);
    t.set_domain("jz", Dom::Reduced);

    for i in (0..=(d - 2)).rev() {
        c_jacobian_double(&mut t, c);
        comb_emit_select(&mut t, i, w, d);

        // `c_jacobian_add_affine_body` documents its layout as
        // [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at the
        // top. The selection leaves ax/ay above jz, so restore the contract
        // before the branch — otherwise the add arm would reorder the stack and
        // the empty else arm would not, leaving the two arms with different
        // layouts at OP_ENDIF.
        t.to_top("_flag");
        t.to_alt();
        t.to_top("jx");
        t.to_top("jy");
        t.to_top("jz");
        t.from_alt("_flag");

        t.pop_tracked(); // consumed by OP_IF
        let safe_i = safe[i];
        let add_ops = collect_ops(|add_emit| {
            if safe_i {
                c_build_jacobian_add_affine_inline(add_emit, &t, c);
            } else {
                c_build_jacobian_add_or_double_inline(add_emit, &t, c);
            }
        });
        (t.e)(StackOp::If { then_ops: add_ops, else_ops: vec![] });

        // The addend was selected fresh for this round; the add only copied it.
        t.to_top("ay");
        t.drop();
        t.to_top("ax");
        t.drop();
    }

    c_jacobian_to_affine(&mut t, "_rx", "_ry", c);

    for j in (1..=entries).rev() {
        t.to_top(&format!("_Ty{}", j));
        t.drop();
        t.to_top(&format!("_Tx{}", j));
        t.drop();
    }
    t.to_top("_k");
    t.drop();

    c_compose_point(&mut t, "_rx", "_ry", "_result", c);
    t.release_constant(POOL_GROUP_N);
    t.release_constant(POOL_FIELD_P);
    true
}

/// Emit the cheapest comb over the candidate window widths.
///
/// Each candidate is rendered in full and scored with the same byte-cost model
/// the emitter is measured by, and the smallest wins.
fn c_emit_comb_best(
    c: &NistCurveParams,
    g: &NistGroupParams,
    curve: &CombCurve,
    opts: Option<&EcCodegenOptions>,
) -> Option<Vec<StackOp>> {
    let mut best: Option<Vec<StackOp>> = None;
    for w in [2usize, 3, 4] {
        let mut ops: Vec<StackOp> = Vec::new();
        let built = {
            let mut sink = |op: StackOp| ops.push(op);
            c_emit_comb_mul_gen(&mut sink, c, g, curve, w, opts)
        };
        if !built {
            continue;
        }
        let better = match &best {
            None => true,
            Some(b) => estimate_script_bytes(&ops) < estimate_script_bytes(b),
        };
        if better {
            best = Some(ops);
        }
    }
    best
}

// ===========================================================================
// Square-and-multiply modular exponentiation (for sqrt)
// ===========================================================================

fn c_field_pow(t: &mut ECTracker, base_name: &str, exp: &BigInt, result_name: &str, c: &NistCurveParams) {
    let bits = exp.bits() as usize;

    // Start: result = base (highest bit = 1)
    t.copy_to_top(base_name, "_pow_r");

    for i in (0..bits - 1).rev() {
        c_field_sqr(t, "_pow_r", "_pow_sq", c);
        t.rename("_pow_r");
        if exp.bit(i as u64) {
            t.copy_to_top(base_name, "_pow_b");
            c_field_mul(t, "_pow_r", "_pow_b", "_pow_m", c);
            t.rename("_pow_r");
        }
    }

    t.to_top(base_name);
    t.drop();
    t.to_top("_pow_r");
    t.rename(result_name);
}

// ===========================================================================
// Pubkey decompression (prefix byte + x -> (x, y))
// ===========================================================================

/// Decompress a compressed pubkey: [prefix||x] → (x_num, y_num, valid).
///
/// For P-256/P-384 where a = -3:
///   y^2 = x^3 - 3x + b mod p
///   y = (y^2)^((p+1)/4) mod p
///   Select y or p-y based on prefix parity.
///
/// `(y^2)^((p+1)/4)` is a square root ONLY when y^2 is a quadratic residue; both
/// primes are ≡ 3 (mod 4), so for a non-residue it returns a square root of
/// -y^2 instead and the recovered point is NOT on the curve. Nor is x checked
/// against p: `c_decompose_point`-style BIN2NUM accepts any width-fitting value
/// and every field op silently reduces it, so a non-canonical x decompresses
/// happily too.
///
/// Both matter because the only consumer is `c_emit_verify_ecdsa`, which feeds
/// the result straight into `c_emit_mul`. That ladder's exception analysis (see
/// `c_build_jacobian_add_or_double_inline`) is stated for points ON the curve,
/// where cofactor 1 pins ord(P) = n; an off-curve point lands on the twist,
/// whose order is composite, so the degenerate steps the interval argument
/// rules out become reachable. The pubkey is a caller-supplied unlock argument.
///
/// So this emits a third output, `_dk_valid` = (x < p) AND (y_cand^2 == y^2)
/// AND (prefix ∈ {0x02, 0x03}), which the caller ANDs into the verifier's
/// boolean result. A flag, not an OP_VERIFY: `verifyECDSA_*` is a total
/// boolean-valued builtin and turning attacker-chosen bytes into a script abort
/// would be a liveness regression — the same argument c_emit_scalar_reduce
/// makes for reducing rather than rejecting.
fn c_decompress_pub_key(
    t: &mut ECTracker,
    pk_name: &str,
    qx_name: &str,
    qy_name: &str,
    c: &NistCurveParams,
    curve_b: &BigInt,
    sqrt_exp: &BigInt,
) {
    t.to_top(pk_name);

    // Split: [prefix_byte, x_bytes]
    t.raw_block(&[pk_name], None, |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(1))));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.push_tracked("_dk_prefix", Dom::Unknown);
    t.push_tracked("_dk_xbytes", Dom::Unknown);

    // SEC1 §2.3.4 requires the prefix to be exactly 0x02 or 0x03. The parity
    // reduction below is `BIN2NUM, 2 MOD`, which accepts far more than that:
    // 0x00 / 0x04 / 0x82 all alias to "even", and 0x83 is worse than an alias —
    // BIN2NUM(0x83) = -3 (sign-magnitude), -3 mod 2 = -1, which encodes as 0x81
    // and can never equal `_dk_y_par` ∈ {<>, 0x01}, so the select silently
    // returns the OTHER square root. Test the byte itself.
    t.copy_to_top("_dk_prefix", "_dk_pfx_in");
    t.raw_block(&["_dk_pfx_in"], Some("_dk_pfx_ok"), |e| {
        e(StackOp::Dup);
        e(StackOp::Push(PushValue::Bytes(vec![0x02])));
        e(StackOp::Opcode("OP_EQUAL".into()));
        e(StackOp::Swap);
        e(StackOp::Push(PushValue::Bytes(vec![0x03])));
        e(StackOp::Opcode("OP_EQUAL".into()));
        e(StackOp::Opcode("OP_BOOLOR".into()));
    });

    // Convert prefix to parity: 0x02 -> 0, 0x03 -> 1
    t.to_top("_dk_prefix");
    t.raw_block(&["_dk_prefix"], Some("_dk_parity"), |e| {
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(2))));
        e(StackOp::Opcode("OP_MOD".into()));
    });

    // Stash parity on altstack
    t.to_top("_dk_parity");
    t.to_alt();

    // Convert x_bytes to number
    let rev_fn = c.reverse_bytes;
    t.to_top("_dk_xbytes");
    t.raw_block(&["_dk_xbytes"], Some("_dk_x"), |e| {
        rev_fn(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Save x for later
    t.copy_to_top("_dk_x", "_dk_x_save");

    // Compute y^2 = x^3 - 3x + b mod p
    t.copy_to_top("_dk_x", "_dk_x_c1");
    c_field_sqr(t, "_dk_x", "_dk_x2", c);
    c_field_mul(t, "_dk_x2", "_dk_x_c1", "_dk_x3", c);
    t.copy_to_top("_dk_x_save", "_dk_x_for_3");
    c_field_mul_const(t, "_dk_x_for_3", 3, "_dk_3x", c);
    c_field_sub(t, "_dk_x3", "_dk_3x", "_dk_x3m3x", c);
    t.push_big("_dk_b", curve_b);
    c_field_add(t, "_dk_x3m3x", "_dk_b", "_dk_y2", c);

    // y = (y^2)^sqrtExp mod p. c_field_pow CONSUMES its base, so keep a copy of
    // y^2 for the residue check at the end. It has to sit BELOW _dk_y_cand: the
    // parity select below is an OP_IF whose branches are a bare drop / nip, so
    // nothing may come between _dk_y_cand and the negated candidate.
    t.copy_to_top("_dk_y2", "_dk_y2_keep");
    c_field_pow(t, "_dk_y2", sqrt_exp, "_dk_y_cand", c);

    // Check if candidate y has the right parity
    t.copy_to_top("_dk_y_cand", "_dk_y_check");
    t.raw_block(&["_dk_y_check"], Some("_dk_y_par"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(2))));
        e(StackOp::Opcode("OP_MOD".into()));
    });

    // Retrieve parity from altstack
    t.from_alt("_dk_parity");

    // Compare
    t.to_top("_dk_y_par");
    t.to_top("_dk_parity");
    t.raw_block(&["_dk_y_par", "_dk_parity"], Some("_dk_match"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });

    // Compute p - y_cand
    t.copy_to_top("_dk_y_cand", "_dk_y_for_neg");
    c_push_field_p(t, "_dk_pfn", c);
    t.to_top("_dk_y_for_neg");
    t.raw_block(&["_dk_pfn", "_dk_y_for_neg"], Some("_dk_neg_y"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });

    // Use OP_IF to select: if match, use y_cand (drop neg_y), else use neg_y (drop y_cand)
    t.to_top("_dk_match");
    t.pop_tracked(); // condition consumed by IF

    let then_ops = vec![StackOp::Drop]; // remove neg_y, leaving y_cand
    let else_ops = vec![StackOp::Nip];  // remove y_cand, leaving neg_y
    (t.e)(StackOp::If { then_ops, else_ops });

    // Remove one from tracker and rename the surviving item
    if let Some(neg_idx) = t.nm.iter().rposition(|n| n == "_dk_neg_y") {
        t.remove_slot_at(neg_idx);
    }
    if let Some(yc_idx) = t.nm.iter().rposition(|n| n == "_dk_y_cand") {
        t.nm[yc_idx] = qy_name.to_string();
        // FORGET what was known about the slot: `_dk_y_cand` carries Reduced from
// cFieldPow, but that fact describes only the THEN path. The else arm leaves
// `p - y_cand` (bare OP_SUB, Unknown, range (0, p]) in this same slot, and
// p - 0 = p is not < p. This is the join ECTracker.emitIf refuses to make, and
// the raw `if` here bypasses that rule, so the reset must be explicit. Sound
// today only via an unwritten argument (y_cand = 0 needs an order-2 point,
// impossible on a prime-order curve) and unexploited only because nothing uses
// qy as a fieldSub subtrahend yet.
        t.set_domain(qy_name, Dom::Unknown);
    }
    if let Some(xs_idx) = t.nm.iter().rposition(|n| n == "_dk_x_save") {
        t.nm[xs_idx] = qx_name.to_string();
    }

    // valid = (qy^2 == y^2) AND (qx < p) AND (prefix ∈ {0x02, 0x03}).
    // The selected qy is y_cand or p - y_cand, so squaring it tests the same
    // residue property either way. The first conjunct rejects an x whose RHS is
    // a quadratic non-residue — the recovered point is then off the curve; the
    // second rejects a non-canonical encoding of an otherwise fine x; the third
    // rejects a prefix byte the parity reduction would otherwise alias or, for
    // 0x83, silently invert.
    t.copy_to_top(qy_name, "_dk_y_sq_in");
    c_field_sqr(t, "_dk_y_sq_in", "_dk_y_sq", c);
    t.to_top("_dk_y_sq");
    t.to_top("_dk_y2_keep");
    t.raw_block(&["_dk_y_sq", "_dk_y2_keep"], Some("_dk_res_ok"), |e| {
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
    });
    t.copy_to_top(qx_name, "_dk_x_lt");
    c_push_field_p(t, "_dk_p_lt", c);
    t.raw_block(&["_dk_x_lt", "_dk_p_lt"], Some("_dk_x_ok"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.to_top("_dk_res_ok");
    t.to_top("_dk_x_ok");
    t.raw_block(&["_dk_res_ok", "_dk_x_ok"], Some("_dk_curve_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.to_top("_dk_pfx_ok");
    t.raw_block(&["_dk_curve_ok", "_dk_pfx_ok"], Some("_dk_valid"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

/// Length gate for an untrusted byte argument: leaves `[flag, clamped]`.
///
/// `flag` is `OP_SIZE(v) == want`; `clamped` is `v` forced to exactly `want`
/// bytes by `v ‖ 00*want`, split at `want`, tail dropped — truncating a long
/// value and zero-extending a short one.
///
/// The clamp exists so the gate can stay a FLAG. Everything downstream peels a
/// fixed number of bytes (`OP_SPLIT coord_bytes`, then 32/48 single-byte splits
/// inside emit_reverse_32/48); handed 32 <= len(sig) < 64 the reversal runs out
/// of bytes mid-loop and the SCRIPT ABORTS, which would make
/// `verifyECDSA_P256(...) || fallback` unwritable and contradict this module's
/// own totality rule (see c_decompress_pub_key). Clamping first makes every path
/// total; the caller ANDs `flag` into the result so a wrong-length argument can
/// never verify whatever the clamped bytes computed.
///
/// Branch-free on purpose: the tracker's static stack model, and the emitted op
/// sequence, are the same for every input length — the argument c_affine_add
/// makes for selecting operands instead of branching.
fn c_emit_length_gate(t: &mut ECTracker, name: &str, want: usize, flag_name: &str) {
    t.to_top(name);
    t.raw_block(&[name], None, |e| {
        e(StackOp::Opcode("OP_SIZE".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(want as i128))));
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
        e(StackOp::Swap);
        e(StackOp::Push(PushValue::Bytes(vec![0u8; want])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(want as i128))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
    });
    t.push_tracked(flag_name, Dom::Unknown);
    t.push_tracked(name, Dom::Unknown);
}

/// SEC1 §4.1.4 step 1 / FIPS 186-5 §6.4.2: verify 1 <= r <= n-1 and
/// 1 <= s <= n-1. Consumes nothing, leaves `_range_ok` above `_r` and `_s`.
///
/// ==> THIS IS A UNIVERSAL FORGERY GUARD, NOT A HYGIENE CHECK. <==
///
/// Nothing checked r or s at all, and `c_group_inv` is Fermat (a^(n-2) mod n),
/// so inv(0) = 0 instead of an error. With `sig = 0x00…` and the contract's own
/// genuine, PUBLIC key:
///
///   r = s = 0            (BIN2NUM of coord_bytes zero bytes -> empty vector)
///   w = s^(n-2) = 0      Fermat, no failure channel
///   u1 = u2 = 0          every c_group_mul in the ladder is 0*0 mod n
///   R1 = R2 = O          c_emit_mul reduces 0, k' = 3n = 0 mod n, so Z3 = 0 and
///                        c_jacobian_to_affine's Fermat inverse turns it all-zero
///   R1 + R2              c_affine_add sees xeq = yeq = 1, takes the tangent
///                        with den = 2*0 = 0, so s = 0 and rx = ry = 0
///   (R.x mod n) == r     OP_EQUAL(<>, <>) = 1
///
/// ...and `_dk_valid` is 1 because the pubkey is genuine. TRUE. No secret, no
/// off-curve point, not bound to the message: an all-zero signature verified for
/// ANY message under ANY public key. `examples/ts/p256-wallet` made exactly that
/// call its second authentication factor.
///
/// BOTH conjuncts are load-bearing and neither is redundant:
///   - s = 0 (or s = n, which Fermat also inverts to 0) is what collapses both
///     ladders to O;
///   - r = 0 is what makes the final OP_EQUAL compare the resulting 0 against
///     something that is also 0.
/// `r = 0, s = n` is a second spelling of the same forgery that an `s != 0`
/// check alone would miss, which is why the bound is `< n` and not `!= 0`.
///
/// A flag rather than an OP_VERIFY, for the reason c_decompress_pub_key gives.
fn c_emit_sig_range_gate(t: &mut ECTracker, g: &NistGroupParams) {
    t.copy_to_top("_r", "_r_nz_in");
    t.raw_block(&["_r_nz_in"], Some("_r_nz"), |e| {
        e(StackOp::Opcode("OP_0NOTEQUAL".into()));
    });
    t.copy_to_top("_r", "_r_lt_in");
    c_push_group_n(t, "_n_for_r", g);
    t.raw_block(&["_r_lt_in", "_n_for_r"], Some("_r_lt"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.raw_block(&["_r_nz", "_r_lt"], Some("_r_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });

    t.copy_to_top("_s", "_s_nz_in");
    t.raw_block(&["_s_nz_in"], Some("_s_nz"), |e| {
        e(StackOp::Opcode("OP_0NOTEQUAL".into()));
    });
    t.copy_to_top("_s", "_s_lt_in");
    c_push_group_n(t, "_n_for_s", g);
    t.raw_block(&["_s_lt_in", "_n_for_s"], Some("_s_lt"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.raw_block(&["_s_nz", "_s_lt"], Some("_s_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });

    t.raw_block(&["_r_ok", "_s_ok"], Some("_range_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
}

fn c_emit_verify_ecdsa(
    emit: &mut dyn FnMut(StackOp),
    c: &NistCurveParams,
    g: &NistGroupParams,
    curve_b: &BigInt,
    sqrt_exp: &BigInt,
    gx: &BigInt,
    gy: &BigInt,
    comb_curve: &CombCurve,
    opts: Option<&EcCodegenOptions>,
) {
    let mut t = ECTracker::with_opts(&["_msg", "_sig", "_pk"], emit, opts, None);
    // The verifier does hundreds of reductions OUTSIDE the two ladders —
    // decompression's sqrt ladder, `c_group_inv`, `c_affine_add`, the final
    // `c_group_mod`. Each ladder pools separately: `c_emit_mul` runs on its own
    // tracker that deliberately cannot see this stack, so it cannot reach this
    // slot.
    t.pool_constant(POOL_FIELD_P, &c.field_p);
    t.pool_constant(POOL_GROUP_N, &g.n);

    // Step 0: length gate. `_sig` and `_pk` are bare ByteString in the builtin
    // table and the type checker imposes no width, so both arrive attacker-sized.
    // Clamp them and remember whether they were the right size — see
    // c_emit_length_gate for why a clamp and not an abort. Without it `sig ‖ junk`
    // verified identically to `sig` (fatal for any contract using signature bytes
    // as a nullifier), and a short `sig` aborted the script outright.
    c_emit_length_gate(&mut t, "_pk", c.coord_bytes + 1, "_pk_len_ok");
    c_emit_length_gate(&mut t, "_sig", c.coord_bytes * 2, "_sig_len_ok");
    t.to_top("_pk_len_ok");
    t.to_top("_sig_len_ok");
    t.raw_block(&["_pk_len_ok", "_sig_len_ok"], Some("_len_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });

    // Step 1: e = SHA-256(msg) as integer
    t.to_top("_msg");
    t.raw_block(&["_msg"], Some("_e"), |e| {
        e(StackOp::Opcode("OP_SHA256".into()));
        emit_reverse_32(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Step 2: Parse sig into (r, s)
    let cb = c.coord_bytes as i128;
    t.to_top("_sig");
    t.raw_block(&["_sig"], None, |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(cb))));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.push_tracked("_r_bytes", Dom::Unknown);
    t.push_tracked("_s_bytes", Dom::Unknown);

    // Convert r_bytes to integer
    let rev_fn = c.reverse_bytes;
    t.to_top("_r_bytes");
    t.raw_block(&["_r_bytes"], Some("_r"), |e| {
        rev_fn(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Convert s_bytes to integer
    t.to_top("_s_bytes");
    t.raw_block(&["_s_bytes"], Some("_s"), |e| {
        rev_fn(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Step 2b: 1 <= r, s <= n-1. Without this an all-zero signature verifies for
    // any message under any pubkey — see c_emit_sig_range_gate.
    c_emit_sig_range_gate(&mut t, g);

    // Step 3: Decompress pubkey. Also yields `_dk_valid`: 0 when the pubkey
    // bytes do not decompress to a canonical on-curve point, which is ANDed into
    // the result below so such a key can never verify.
    c_decompress_pub_key(&mut t, "_pk", "_qx", "_qy", c, curve_b, sqrt_exp);

    // Collapse the three argument verdicts into one flag. Everything below then
    // carries a single item, as it did when `_dk_valid` was the only one.
    t.to_top("_len_ok");
    t.to_top("_range_ok");
    t.raw_block(&["_len_ok", "_range_ok"], Some("_arg_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.to_top("_dk_valid");
    t.raw_block(&["_arg_ok", "_dk_valid"], Some("_input_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });

    // Step 4: w = s^{-1} mod n
    c_group_inv(&mut t, "_s", "_w", g);

    // Step 5: u1 = e * w mod n
    t.copy_to_top("_w", "_w_c1");
    c_group_mul(&mut t, "_e", "_w_c1", "_u1", g);

    // Step 6: u2 = r * w mod n
    t.copy_to_top("_r", "_r_save");
    c_group_mul(&mut t, "_r", "_w", "_u2", g);

    // Step 7: R = u1*G + u2*Q
    let point_bytes = c.coord_bytes * 2;
    let mut g_point_data = vec![0u8; point_bytes];
    let gx_bytes = bigint_to_n_bytes(gx, c.coord_bytes);
    let gy_bytes = bigint_to_n_bytes(gy, c.coord_bytes);
    g_point_data[..c.coord_bytes].copy_from_slice(&gx_bytes);
    g_point_data[c.coord_bytes..].copy_from_slice(&gy_bytes);

    // u1*G. G is a compile-time constant, so this half can use a fixed-base
    // comb — one doubling and one add per COLUMN instead of per bit. u2*Q below
    // cannot: Q arrives in the witness.
    let comb_ops = if opts.map(|o| o.fixed_base_comb).unwrap_or(false) {
        c_emit_comb_best(c, g, comb_curve, opts)
    } else {
        None
    };

    if comb_ops.is_none() {
        t.push_bytes("_G", g_point_data);
    }
    t.to_top("_u1");

    // Stash items on altstack.
    // _input_ok goes DEEPEST — the altstack is LIFO and it is popped last.
    t.to_top("_input_ok");
    t.to_alt();
    t.to_top("_r_save");
    t.to_alt();
    t.to_top("_u2");
    t.to_alt();
    t.to_top("_qy");
    t.to_alt();
    t.to_top("_qx");
    t.to_alt();

    // The multiply creates its own ECTracker and cannot see items below its
    // operands. Remove them from ours.
    t.pop_tracked(); // _u1
    if comb_ops.is_none() {
        t.pop_tracked(); // _G
    }

    match &comb_ops {
        Some(ops) => {
            for op in ops {
                (t.e)(op.clone());
            }
        }
        None => c_emit_mul(t.e, c, g, opts),
    }

    // After mul, one result point is on the stack
    t.push_tracked("_R1_point", Dom::Unknown);

    // Pop qx/qy/u2 from altstack (LIFO order)
    t.from_alt("_qx");
    t.from_alt("_qy");
    t.from_alt("_u2");

    // Stash R1 point
    t.to_top("_R1_point");
    t.to_alt();

    // Compose Q point
    c_compose_point(&mut t, "_qx", "_qy", "_Q_point", c);

    t.to_top("_u2");

    // Remove from tracker, emit mul, push result
    t.pop_tracked(); // _u2
    t.pop_tracked(); // _Q_point
    c_emit_mul(t.e, c, g, opts);
    t.push_tracked("_R2_point", Dom::Unknown);

    // Restore R1 point
    t.from_alt("_R1_point");

    // Swap so R2 is on top
    t.swap();

    // Decompose both, add, compose
    c_decompose_point(&mut t, "_R1_point", "_rpx", "_rpy", c);
    c_decompose_point(&mut t, "_R2_point", "_rqx", "_rqy", c);

    // Rename to what c_affine_add expects
    if let Some(idx) = t.nm.iter().rposition(|n| n == "_rpx") { t.nm[idx] = "px".to_string(); }
    if let Some(idx) = t.nm.iter().rposition(|n| n == "_rpy") { t.nm[idx] = "py".to_string(); }
    if let Some(idx) = t.nm.iter().rposition(|n| n == "_rqx") { t.nm[idx] = "qx".to_string(); }
    if let Some(idx) = t.nm.iter().rposition(|n| n == "_rqy") { t.nm[idx] = "qy".to_string(); }

    c_affine_add(&mut t, c);

    // Step 8: x_R mod n == r
    t.to_top("ry");
    t.drop();

    c_group_mod(&mut t, "rx", "_rx_mod_n", g);

    // Restore r, then the argument verdict beneath it
    t.from_alt("_r_save");
    t.from_alt("_input_ok");

    // Compare
    t.to_top("_rx_mod_n");
    t.to_top("_r_save");
    t.raw_block(&["_rx_mod_n", "_r_save"], Some("_sig_ok"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });

    // Arguments that were the wrong length, out of range, or did not decompress
    // to a canonical on-curve point can never verify, whatever the ladder made
    // of them.
    t.to_top("_input_ok");
    t.to_top("_sig_ok");
    t.raw_block(&["_input_ok", "_sig_ok"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.release_constant(POOL_GROUP_N);
    t.release_constant(POOL_FIELD_P);
}

// ===========================================================================
// P-256 public API
// ===========================================================================

/// p256Add: add two P-256 points.
pub fn emit_p256_add(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pa", "_pb"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P256_CURVE.field_p);
    c_decompose_point(&mut t, "_pa", "px", "py", &P256_CURVE);
    c_decompose_point(&mut t, "_pb", "qx", "qy", &P256_CURVE);
    c_affine_add(&mut t, &P256_CURVE);
    c_compose_point(&mut t, "rx", "ry", "_result", &P256_CURVE);
    t.release_constant(POOL_FIELD_P);
}

/// p256Mul: P-256 scalar multiplication.
pub fn emit_p256_mul(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    c_emit_mul(emit, &P256_CURVE, &P256_GROUP, opts);
}

/// p256MulGen: P-256 generator multiplication.
pub fn emit_p256_mul_gen(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    if opts.map(|o| o.fixed_base_comb).unwrap_or(false) {
        if let Some(ops) = c_emit_comb_best(&P256_CURVE, &P256_GROUP, &P256_COMB_CURVE, opts) {
            for op in ops {
                emit(op);
            }
            return;
        }
    }
    let mut g_point = Vec::with_capacity(64);
    g_point.extend_from_slice(&bigint_to_n_bytes(&P256_GX, 32));
    g_point.extend_from_slice(&bigint_to_n_bytes(&P256_GY, 32));
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_p256_mul(emit, opts);
}

/// p256Negate: negate a P-256 point.
pub fn emit_p256_negate(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P256_CURVE.field_p);
    c_decompose_point(&mut t, "_pt", "_nx", "_ny", &P256_CURVE);
    c_push_field_p(&mut t, "_fp", &P256_CURVE);
    c_field_sub(&mut t, "_fp", "_ny", "_neg_y", &P256_CURVE);
    c_compose_point(&mut t, "_nx", "_neg_y", "_result", &P256_CURVE);
    t.release_constant(POOL_FIELD_P);
}

/// p256OnCurve: check if a P-256 point is on the curve (y^2 = x^3 - 3x + b mod p).
pub fn emit_p256_on_curve(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P256_CURVE.field_p);
    c_decompose_point(&mut t, "_pt", "_x", "_y", &P256_CURVE);
    c_emit_canonicity_guard(&mut t, "_x", "_y", &P256_CURVE);

    // lhs = y^2
    c_field_sqr(&mut t, "_y", "_y2", &P256_CURVE);

    // rhs = x^3 - 3x + b
    t.copy_to_top("_x", "_x_copy");
    t.copy_to_top("_x", "_x_copy2");
    c_field_sqr(&mut t, "_x", "_x2", &P256_CURVE);
    c_field_mul(&mut t, "_x2", "_x_copy", "_x3", &P256_CURVE);
    c_field_mul_const(&mut t, "_x_copy2", 3, "_3x", &P256_CURVE);
    c_field_sub(&mut t, "_x3", "_3x", "_x3m3x", &P256_CURVE);
    t.push_big("_b", &P256_B);
    c_field_add(&mut t, "_x3m3x", "_b", "_rhs", &P256_CURVE);

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_curve_eq"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });

    // on-curve = canonical AND curve-equation
    t.to_top("_canon");
    t.to_top("_curve_eq");
    t.raw_block(&["_canon", "_curve_eq"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.release_constant(POOL_FIELD_P);
}

/// p256EncodeCompressed: encode a P-256 point as 33-byte compressed pubkey.
pub fn emit_p256_encode_compressed(emit: &mut dyn FnMut(StackOp)) {
    // Split at 32: [x_bytes, y_bytes]
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Get last byte of y for parity
    emit(StackOp::Opcode("OP_SIZE".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(1))));
    emit(StackOp::Opcode("OP_SUB".into()));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Stack: [x_bytes, y_prefix, last_byte]
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(2))));
    emit(StackOp::Opcode("OP_MOD".into()));
    // Stack: [x_bytes, y_prefix, parity]
    emit(StackOp::Swap);
    emit(StackOp::Drop); // drop y_prefix
    // Stack: [x_bytes, parity]
    emit(StackOp::If {
        then_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x03]))],
        else_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x02]))],
    });
    // Stack: [x_bytes, prefix_byte]
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_CAT".into()));
}

/// verifyECDSA_P256: verify an ECDSA signature on P-256.
pub fn emit_verify_ecdsa_p256(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    c_emit_verify_ecdsa(emit, &P256_CURVE, &P256_GROUP, &P256_B, &P256_SQRT_EXP, &P256_GX, &P256_GY, &P256_COMB_CURVE, opts);
}

// ===========================================================================
// P-384 public API
// ===========================================================================

/// p384Add: add two P-384 points.
pub fn emit_p384_add(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pa", "_pb"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P384_CURVE.field_p);
    c_decompose_point(&mut t, "_pa", "px", "py", &P384_CURVE);
    c_decompose_point(&mut t, "_pb", "qx", "qy", &P384_CURVE);
    c_affine_add(&mut t, &P384_CURVE);
    c_compose_point(&mut t, "rx", "ry", "_result", &P384_CURVE);
    t.release_constant(POOL_FIELD_P);
}

/// p384Mul: P-384 scalar multiplication.
pub fn emit_p384_mul(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    c_emit_mul(emit, &P384_CURVE, &P384_GROUP, opts);
}

/// p384MulGen: P-384 generator multiplication.
pub fn emit_p384_mul_gen(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    if opts.map(|o| o.fixed_base_comb).unwrap_or(false) {
        if let Some(ops) = c_emit_comb_best(&P384_CURVE, &P384_GROUP, &P384_COMB_CURVE, opts) {
            for op in ops {
                emit(op);
            }
            return;
        }
    }
    let mut g_point = Vec::with_capacity(96);
    g_point.extend_from_slice(&bigint_to_n_bytes(&P384_GX, 48));
    g_point.extend_from_slice(&bigint_to_n_bytes(&P384_GY, 48));
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_p384_mul(emit, opts);
}

/// p384Negate: negate a P-384 point.
pub fn emit_p384_negate(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P384_CURVE.field_p);
    c_decompose_point(&mut t, "_pt", "_nx", "_ny", &P384_CURVE);
    c_push_field_p(&mut t, "_fp", &P384_CURVE);
    c_field_sub(&mut t, "_fp", "_ny", "_neg_y", &P384_CURVE);
    c_compose_point(&mut t, "_nx", "_neg_y", "_result", &P384_CURVE);
    t.release_constant(POOL_FIELD_P);
}

/// p384OnCurve: check if a P-384 point is on the curve.
pub fn emit_p384_on_curve(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &P384_CURVE.field_p);
    c_decompose_point(&mut t, "_pt", "_x", "_y", &P384_CURVE);
    c_emit_canonicity_guard(&mut t, "_x", "_y", &P384_CURVE);

    // lhs = y^2
    c_field_sqr(&mut t, "_y", "_y2", &P384_CURVE);

    // rhs = x^3 - 3x + b
    t.copy_to_top("_x", "_x_copy");
    t.copy_to_top("_x", "_x_copy2");
    c_field_sqr(&mut t, "_x", "_x2", &P384_CURVE);
    c_field_mul(&mut t, "_x2", "_x_copy", "_x3", &P384_CURVE);
    c_field_mul_const(&mut t, "_x_copy2", 3, "_3x", &P384_CURVE);
    c_field_sub(&mut t, "_x3", "_3x", "_x3m3x", &P384_CURVE);
    t.push_big("_b", &P384_B);
    c_field_add(&mut t, "_x3m3x", "_b", "_rhs", &P384_CURVE);

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_curve_eq"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });

    // on-curve = canonical AND curve-equation
    t.to_top("_canon");
    t.to_top("_curve_eq");
    t.raw_block(&["_canon", "_curve_eq"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.release_constant(POOL_FIELD_P);
}

/// p384EncodeCompressed: encode a P-384 point as 49-byte compressed pubkey.
pub fn emit_p384_encode_compressed(emit: &mut dyn FnMut(StackOp)) {
    // Split at 48: [x_bytes, y_bytes]
    emit(StackOp::Push(PushValue::Int(BigInt::from(48))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Get last byte of y for parity
    emit(StackOp::Opcode("OP_SIZE".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(1))));
    emit(StackOp::Opcode("OP_SUB".into()));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Stack: [x_bytes, y_prefix, last_byte]
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(2))));
    emit(StackOp::Opcode("OP_MOD".into()));
    // Stack: [x_bytes, y_prefix, parity]
    emit(StackOp::Swap);
    emit(StackOp::Drop); // drop y_prefix
    // Stack: [x_bytes, parity]
    emit(StackOp::If {
        then_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x03]))],
        else_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x02]))],
    });
    // Stack: [x_bytes, prefix_byte]
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_CAT".into()));
}

/// verifyECDSA_P384: verify an ECDSA signature on P-384.
pub fn emit_verify_ecdsa_p384(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    c_emit_verify_ecdsa(emit, &P384_CURVE, &P384_GROUP, &P384_B, &P384_SQRT_EXP, &P384_GX, &P384_GY, &P384_COMB_CURVE, opts);
}
