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
        e(StackOp::Push(PushValue::Int(1)));
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

// ===========================================================================
// ECTracker (same as in ec.rs — duplicated since it's private there)
// ===========================================================================

struct ECTracker<'a> {
    nm: Vec<String>,
    e: &'a mut dyn FnMut(StackOp),
}

#[allow(dead_code)]
impl<'a> ECTracker<'a> {
    fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        ECTracker {
            nm: init.iter().map(|s| s.to_string()).collect(),
            e: emit,
        }
    }

    fn depth(&self) -> usize { self.nm.len() }

    fn find_depth(&self, name: &str) -> usize {
        for i in (0..self.nm.len()).rev() {
            if self.nm[i] == name {
                return self.nm.len() - 1 - i;
            }
        }
        panic!("ECTracker: '{}' not on stack {:?}", name, self.nm);
    }

    fn push_bytes(&mut self, n: &str, v: Vec<u8>) {
        (self.e)(StackOp::Push(PushValue::Bytes(v)));
        self.nm.push(n.to_string());
    }

    fn push_int(&mut self, n: &str, v: i128) {
        (self.e)(StackOp::Push(PushValue::Int(v)));
        self.nm.push(n.to_string());
    }

    fn push_big_int(&mut self, n: &str, v: &BigInt) {
        let script_num = bigint_to_script_num(v);
        (self.e)(StackOp::Push(PushValue::Bytes(script_num)));
        self.nm.push(n.to_string());
    }

    fn dup(&mut self, n: &str) {
        (self.e)(StackOp::Dup);
        self.nm.push(n.to_string());
    }

    fn drop(&mut self) {
        (self.e)(StackOp::Drop);
        if !self.nm.is_empty() { self.nm.pop(); }
    }

    fn nip(&mut self) {
        (self.e)(StackOp::Nip);
        let len = self.nm.len();
        if len >= 2 { self.nm.remove(len - 2); }
    }

    fn over(&mut self, n: &str) {
        (self.e)(StackOp::Over);
        self.nm.push(n.to_string());
    }

    fn swap(&mut self) {
        (self.e)(StackOp::Swap);
        let len = self.nm.len();
        if len >= 2 { self.nm.swap(len - 1, len - 2); }
    }

    fn rot(&mut self) {
        (self.e)(StackOp::Rot);
        let len = self.nm.len();
        if len >= 3 {
            let r = self.nm.remove(len - 3);
            self.nm.push(r);
        }
    }

    fn op(&mut self, code: &str) {
        (self.e)(StackOp::Opcode(code.into()));
    }

    fn roll(&mut self, d: usize) {
        if d == 0 { return; }
        if d == 1 { self.swap(); return; }
        if d == 2 { self.rot(); return; }
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_ROLL".into()));
        self.nm.pop();
        let idx = self.nm.len() - 1 - d;
        let r = self.nm.remove(idx);
        self.nm.push(r);
    }

    fn pick(&mut self, d: usize, n: &str) {
        if d == 0 { self.dup(n); return; }
        if d == 1 { self.over(n); return; }
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_PICK".into()));
        self.nm.pop();
        self.nm.push(n.to_string());
    }

    fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        self.roll(d);
    }

    fn copy_to_top(&mut self, name: &str, n: &str) {
        let d = self.find_depth(name);
        self.pick(d, n);
    }

    fn to_alt(&mut self) {
        self.op("OP_TOALTSTACK");
        if !self.nm.is_empty() { self.nm.pop(); }
    }

    fn from_alt(&mut self, n: &str) {
        self.op("OP_FROMALTSTACK");
        self.nm.push(n.to_string());
    }

    fn rename(&mut self, n: &str) {
        if let Some(last) = self.nm.last_mut() {
            *last = n.to_string();
        }
    }

    fn raw_block(
        &mut self,
        consume: &[&str],
        produce: Option<&str>,
        f: impl FnOnce(&mut dyn FnMut(StackOp)),
    ) {
        for _ in consume {
            if !self.nm.is_empty() { self.nm.pop(); }
        }
        f(self.e);
        if let Some(p) = produce {
            self.nm.push(p.to_string());
        }
    }
}

// ===========================================================================
// Generic curve field arithmetic (parameterized by prime)
// ===========================================================================

fn c_push_field_p(t: &mut ECTracker, name: &str, c: &NistCurveParams) {
    t.push_big_int(name, &*c.field_p);
}

fn c_field_mod(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
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
}

fn c_field_add(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fadd_sum"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    c_field_mod(t, "_fadd_sum", result_name, c);
}

fn c_field_sub(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fsub_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    c_field_mod(t, "_fsub_diff", result_name, c);
}

fn c_field_mul(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fmul_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    c_field_mod(t, "_fmul_prod", result_name, c);
}

fn c_field_mul_const(t: &mut ECTracker, a_name: &str, cv: i128, result_name: &str, c: &NistCurveParams) {
    t.to_top(a_name);
    t.raw_block(&[a_name], Some("_fmc_prod"), |e| {
        if cv == 2 {
            e(StackOp::Opcode("OP_2MUL".into()));
        } else {
            e(StackOp::Push(PushValue::Int(cv)));
            e(StackOp::Opcode("OP_MUL".into()));
        }
    });
    c_field_mod(t, "_fmc_prod", result_name, c);
}

fn c_field_sqr(t: &mut ECTracker, a_name: &str, result_name: &str, c: &NistCurveParams) {
    t.copy_to_top(a_name, "_fsqr_copy");
    c_field_mul(t, a_name, "_fsqr_copy", result_name, c);
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
    t.push_big_int(name, &*g.n);
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
        e(StackOp::Push(PushValue::Int(c.coord_bytes as i128)));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.nm.push("_dp_xb".to_string());
    t.nm.push("_dp_yb".to_string());

    // Convert y_bytes (on top) to num
    t.raw_block(&["_dp_yb"], Some(y_name), |e| {
        (c.reverse_bytes)(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Convert x_bytes to num
    t.to_top("_dp_xb");
    t.raw_block(&["_dp_xb"], Some(x_name), |e| {
        (c.reverse_bytes)(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

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
        e(StackOp::Push(PushValue::Int(num_bin_size)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(cb)));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        rev_fn(e);
    });

    // Convert y to coordBytes big-endian
    t.to_top(y_name);
    t.raw_block(&[y_name], Some("_cp_yb"), |e| {
        e(StackOp::Push(PushValue::Int(num_bin_size)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(cb)));
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

fn c_affine_add(t: &mut ECTracker, c: &NistCurveParams) {
    // s_num = qy - py
    t.copy_to_top("qy", "_qy1");
    t.copy_to_top("py", "_py1");
    c_field_sub(t, "_qy1", "_py1", "_s_num", c);

    // s_den = qx - px
    t.copy_to_top("qx", "_qx1");
    t.copy_to_top("px", "_px1");
    c_field_sub(t, "_qx1", "_px1", "_s_den", c);

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
    let mut it = ECTracker::new(&init_strs, e);

    it.copy_to_top("jz", "_jz_for_z1cu");
    it.copy_to_top("jz", "_jz_for_z3");
    it.copy_to_top("jy", "_jy_for_y3");
    it.copy_to_top("jx", "_jx_for_u1h2");

    // Z1sq = jz^2
    c_field_sqr(&mut it, "jz", "_Z1sq", c);

    // Z1cu = _jz_for_z1cu * Z1sq
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2");
    c_field_mul(&mut it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", c);

    // U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c");
    c_field_mul(&mut it, "_ax_c", "_Z1sq_for_u2", "_U2", c);

    // S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c");
    c_field_mul(&mut it, "_ay_c", "_Z1cu", "_S2", c);

    // H = U2 - jx
    c_field_sub(&mut it, "_U2", "jx", "_H", c);

    // R = S2 - jy
    c_field_sub(&mut it, "_S2", "jy", "_R", c);

    it.copy_to_top("_H", "_H_for_h3");
    it.copy_to_top("_H", "_H_for_z3");

    // H2 = H^2
    c_field_sqr(&mut it, "_H", "_H2", c);

    it.copy_to_top("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    c_field_mul(&mut it, "_H_for_h3", "_H2", "_H3", c);

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    c_field_mul(&mut it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", c);

    it.copy_to_top("_R", "_R_for_y3");
    it.copy_to_top("_U1H2", "_U1H2_for_y3");
    it.copy_to_top("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    c_field_sqr(&mut it, "_R", "_R2", c);
    c_field_sub(&mut it, "_R2", "_H3", "_x3_tmp", c);
    c_field_mul_const(&mut it, "_U1H2", 2, "_2U1H2", c);
    c_field_sub(&mut it, "_x3_tmp", "_2U1H2", "_X3", c);

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c");
    c_field_sub(&mut it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", c);
    c_field_mul(&mut it, "_R_for_y3", "_u_minus_x", "_r_tmp", c);
    c_field_mul(&mut it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", c);
    c_field_sub(&mut it, "_r_tmp", "_jy_h3", "_Y3", c);

    // Z3 = _jz_for_z3 * _H_for_z3
    c_field_mul(&mut it, "_jz_for_z3", "_H_for_z3", "_Z3", c);

    it.to_top("_X3"); it.rename("jx");
    it.to_top("_Y3"); it.rename("jy");
    it.to_top("_Z3"); it.rename("jz");
}

// ===========================================================================
// Scalar multiplication (generic for both P-256 and P-384)
// ===========================================================================

fn c_emit_mul(emit: &mut dyn FnMut(StackOp), c: &NistCurveParams, g: &NistGroupParams) {
    let mut t = ECTracker::new(&["_pt", "_k"], emit);
    c_decompose_point(&mut t, "_pt", "ax", "ay", c);

    // k' = k + 3n (pre-compute 3n to match Go peephole optimizer output)
    t.to_top("_k");
    let three_n = &**g.n * 3;
    t.push_big_int("_3n", &three_n);
    t.raw_block(&["_k", "_3n"], Some("_kn3"), |e| {
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
        t.nm.pop(); // _bit consumed by IF
        let add_ops = collect_ops(|add_emit| {
            c_build_jacobian_add_affine_inline(add_emit, &t, c);
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
        e(StackOp::Push(PushValue::Int(1)));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.nm.push("_dk_prefix".to_string());
    t.nm.push("_dk_xbytes".to_string());

    // Convert prefix to parity: 0x02 -> 0, 0x03 -> 1
    t.to_top("_dk_prefix");
    t.raw_block(&["_dk_prefix"], Some("_dk_parity"), |e| {
        e(StackOp::Opcode("OP_BIN2NUM".into()));
        e(StackOp::Push(PushValue::Int(2)));
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
    t.push_big_int("_dk_b", curve_b);
    c_field_add(t, "_dk_x3m3x", "_dk_b", "_dk_y2", c);

    // y = (y^2)^sqrtExp mod p
    c_field_pow(t, "_dk_y2", sqrt_exp, "_dk_y_cand", c);

    // Check if candidate y has the right parity
    t.copy_to_top("_dk_y_cand", "_dk_y_check");
    t.raw_block(&["_dk_y_check"], Some("_dk_y_par"), |e| {
        e(StackOp::Push(PushValue::Int(2)));
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
    t.nm.pop(); // condition consumed by IF

    let then_ops = vec![StackOp::Drop]; // remove neg_y, leaving y_cand
    let else_ops = vec![StackOp::Nip];  // remove y_cand, leaving neg_y
    (t.e)(StackOp::If { then_ops, else_ops });

    // Remove one from tracker and rename the surviving item
    if let Some(neg_idx) = t.nm.iter().rposition(|n| n == "_dk_neg_y") {
        t.nm.remove(neg_idx);
    }
    if let Some(yc_idx) = t.nm.iter().rposition(|n| n == "_dk_y_cand") {
        t.nm[yc_idx] = qy_name.to_string();
    }
    if let Some(xs_idx) = t.nm.iter().rposition(|n| n == "_dk_x_save") {
        t.nm[xs_idx] = qx_name.to_string();
    }
}

// ===========================================================================
// ECDSA verification
// ===========================================================================

fn c_emit_verify_ecdsa(
    emit: &mut dyn FnMut(StackOp),
    c: &NistCurveParams,
    g: &NistGroupParams,
    curve_b: &BigInt,
    sqrt_exp: &BigInt,
    gx: &BigInt,
    gy: &BigInt,
) {
    let mut t = ECTracker::new(&["_msg", "_sig", "_pk"], emit);

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
        e(StackOp::Push(PushValue::Int(cb)));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    t.nm.push("_r_bytes".to_string());
    t.nm.push("_s_bytes".to_string());

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

    // Step 3: Decompress pubkey
    c_decompress_pub_key(&mut t, "_pk", "_qx", "_qy", c, curve_b, sqrt_exp);

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

    t.push_bytes("_G", g_point_data);
    t.to_top("_u1");

    // Stash items on altstack
    t.to_top("_r_save");
    t.to_alt();
    t.to_top("_u2");
    t.to_alt();
    t.to_top("_qy");
    t.to_alt();
    t.to_top("_qx");
    t.to_alt();

    // Remove _G and _u1 from tracker before c_emit_mul
    t.nm.pop(); // _u1
    t.nm.pop(); // _G

    c_emit_mul(t.e, c, g);

    // After mul, one result point is on the stack
    t.nm.push("_R1_point".to_string());

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
    t.nm.pop(); // _u2
    t.nm.pop(); // _Q_point
    c_emit_mul(t.e, c, g);
    t.nm.push("_R2_point".to_string());

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

    // Restore r
    t.from_alt("_r_save");

    // Compare
    t.to_top("_rx_mod_n");
    t.to_top("_r_save");
    t.raw_block(&["_rx_mod_n", "_r_save"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });
}

// ===========================================================================
// P-256 public API
// ===========================================================================

/// p256Add: add two P-256 points.
pub fn emit_p256_add(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pa", "_pb"], emit);
    c_decompose_point(&mut t, "_pa", "px", "py", &P256_CURVE);
    c_decompose_point(&mut t, "_pb", "qx", "qy", &P256_CURVE);
    c_affine_add(&mut t, &P256_CURVE);
    c_compose_point(&mut t, "rx", "ry", "_result", &P256_CURVE);
}

/// p256Mul: P-256 scalar multiplication.
pub fn emit_p256_mul(emit: &mut dyn FnMut(StackOp)) {
    c_emit_mul(emit, &P256_CURVE, &P256_GROUP);
}

/// p256MulGen: P-256 generator multiplication.
pub fn emit_p256_mul_gen(emit: &mut dyn FnMut(StackOp)) {
    let mut g_point = Vec::with_capacity(64);
    g_point.extend_from_slice(&bigint_to_n_bytes(&P256_GX, 32));
    g_point.extend_from_slice(&bigint_to_n_bytes(&P256_GY, 32));
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_p256_mul(emit);
}

/// p256Negate: negate a P-256 point.
pub fn emit_p256_negate(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);
    c_decompose_point(&mut t, "_pt", "_nx", "_ny", &P256_CURVE);
    c_push_field_p(&mut t, "_fp", &P256_CURVE);
    c_field_sub(&mut t, "_fp", "_ny", "_neg_y", &P256_CURVE);
    c_compose_point(&mut t, "_nx", "_neg_y", "_result", &P256_CURVE);
}

/// p256OnCurve: check if a P-256 point is on the curve (y^2 = x^3 - 3x + b mod p).
pub fn emit_p256_on_curve(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);
    c_decompose_point(&mut t, "_pt", "_x", "_y", &P256_CURVE);

    // lhs = y^2
    c_field_sqr(&mut t, "_y", "_y2", &P256_CURVE);

    // rhs = x^3 - 3x + b
    t.copy_to_top("_x", "_x_copy");
    t.copy_to_top("_x", "_x_copy2");
    c_field_sqr(&mut t, "_x", "_x2", &P256_CURVE);
    c_field_mul(&mut t, "_x2", "_x_copy", "_x3", &P256_CURVE);
    c_field_mul_const(&mut t, "_x_copy2", 3, "_3x", &P256_CURVE);
    c_field_sub(&mut t, "_x3", "_3x", "_x3m3x", &P256_CURVE);
    t.push_big_int("_b", &P256_B);
    c_field_add(&mut t, "_x3m3x", "_b", "_rhs", &P256_CURVE);

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });
}

/// p256EncodeCompressed: encode a P-256 point as 33-byte compressed pubkey.
pub fn emit_p256_encode_compressed(emit: &mut dyn FnMut(StackOp)) {
    // Split at 32: [x_bytes, y_bytes]
    emit(StackOp::Push(PushValue::Int(32)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Get last byte of y for parity
    emit(StackOp::Opcode("OP_SIZE".into()));
    emit(StackOp::Push(PushValue::Int(1)));
    emit(StackOp::Opcode("OP_SUB".into()));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Stack: [x_bytes, y_prefix, last_byte]
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
    emit(StackOp::Push(PushValue::Int(2)));
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
pub fn emit_verify_ecdsa_p256(emit: &mut dyn FnMut(StackOp)) {
    c_emit_verify_ecdsa(emit, &P256_CURVE, &P256_GROUP, &P256_B, &P256_SQRT_EXP, &P256_GX, &P256_GY);
}

// ===========================================================================
// P-384 public API
// ===========================================================================

/// p384Add: add two P-384 points.
pub fn emit_p384_add(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pa", "_pb"], emit);
    c_decompose_point(&mut t, "_pa", "px", "py", &P384_CURVE);
    c_decompose_point(&mut t, "_pb", "qx", "qy", &P384_CURVE);
    c_affine_add(&mut t, &P384_CURVE);
    c_compose_point(&mut t, "rx", "ry", "_result", &P384_CURVE);
}

/// p384Mul: P-384 scalar multiplication.
pub fn emit_p384_mul(emit: &mut dyn FnMut(StackOp)) {
    c_emit_mul(emit, &P384_CURVE, &P384_GROUP);
}

/// p384MulGen: P-384 generator multiplication.
pub fn emit_p384_mul_gen(emit: &mut dyn FnMut(StackOp)) {
    let mut g_point = Vec::with_capacity(96);
    g_point.extend_from_slice(&bigint_to_n_bytes(&P384_GX, 48));
    g_point.extend_from_slice(&bigint_to_n_bytes(&P384_GY, 48));
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_p384_mul(emit);
}

/// p384Negate: negate a P-384 point.
pub fn emit_p384_negate(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);
    c_decompose_point(&mut t, "_pt", "_nx", "_ny", &P384_CURVE);
    c_push_field_p(&mut t, "_fp", &P384_CURVE);
    c_field_sub(&mut t, "_fp", "_ny", "_neg_y", &P384_CURVE);
    c_compose_point(&mut t, "_nx", "_neg_y", "_result", &P384_CURVE);
}

/// p384OnCurve: check if a P-384 point is on the curve.
pub fn emit_p384_on_curve(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);
    c_decompose_point(&mut t, "_pt", "_x", "_y", &P384_CURVE);

    // lhs = y^2
    c_field_sqr(&mut t, "_y", "_y2", &P384_CURVE);

    // rhs = x^3 - 3x + b
    t.copy_to_top("_x", "_x_copy");
    t.copy_to_top("_x", "_x_copy2");
    c_field_sqr(&mut t, "_x", "_x2", &P384_CURVE);
    c_field_mul(&mut t, "_x2", "_x_copy", "_x3", &P384_CURVE);
    c_field_mul_const(&mut t, "_x_copy2", 3, "_3x", &P384_CURVE);
    c_field_sub(&mut t, "_x3", "_3x", "_x3m3x", &P384_CURVE);
    t.push_big_int("_b", &P384_B);
    c_field_add(&mut t, "_x3m3x", "_b", "_rhs", &P384_CURVE);

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });
}

/// p384EncodeCompressed: encode a P-384 point as 49-byte compressed pubkey.
pub fn emit_p384_encode_compressed(emit: &mut dyn FnMut(StackOp)) {
    // Split at 48: [x_bytes, y_bytes]
    emit(StackOp::Push(PushValue::Int(48)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Get last byte of y for parity
    emit(StackOp::Opcode("OP_SIZE".into()));
    emit(StackOp::Push(PushValue::Int(1)));
    emit(StackOp::Opcode("OP_SUB".into()));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Stack: [x_bytes, y_prefix, last_byte]
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
    emit(StackOp::Push(PushValue::Int(2)));
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
pub fn emit_verify_ecdsa_p384(emit: &mut dyn FnMut(StackOp)) {
    c_emit_verify_ecdsa(emit, &P384_CURVE, &P384_GROUP, &P384_B, &P384_SQRT_EXP, &P384_GX, &P384_GY);
}
