//! EC codegen — secp256k1 elliptic curve operations for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/ec-codegen.ts.
//! All helpers are self-contained.
//!
//! Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
//! Internal arithmetic uses Jacobian coordinates for scalar multiplication.

use num_bigint::BigInt;
use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// Low 32 bits of (p - 2) = 0xFFFFFC2D.
const FIELD_P_MINUS_2_LOW32: u32 = 0xFFFF_FC2D;

/// 3 * secp256k1 curve order as a script number (little-endian sign-magnitude).
/// Pre-computed to match TS constant-fold output (TS folds N+N+N → 3*N).
const THREE_CURVE_N_SCRIPT_NUM: [u8; 33] = [
    0xc3, 0xc3, 0xa2, 0x70, 0xa6, 0x1b, 0x77, 0x3f, 0xb3, 0xe0, 0xd9, 0x0d,
    0xb4, 0x96, 0x0c, 0x30, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
];

/// secp256k1 curve order n as a script number (little-endian sign-magnitude).
/// Used by `emit_scalar_reduce`; the trailing 0x00 is the sign byte.
const CURVE_N_SCRIPT_NUM: [u8; 33] = [
    0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf, 0x3b, 0xa0, 0x48, 0xaf,
    0xe6, 0xdc, 0xae, 0xba, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
];

/// secp256k1 generator x-coordinate (32 bytes, big-endian).
const GEN_X_BYTES: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95,
    0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

/// secp256k1 generator y-coordinate (32 bytes, big-endian).
const GEN_Y_BYTES: [u8; 32] = [
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
    0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
    0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

/// Collect ops into a Vec via closure.
fn collect_ops(f: impl FnOnce(&mut dyn FnMut(StackOp))) -> Vec<StackOp> {
    let mut ops = Vec::new();
    f(&mut |op| ops.push(op));
    ops
}

// ===========================================================================
// ECTracker — named stack state tracker (mirrors SLHTracker)
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

    fn depth(&self) -> usize {
        self.nm.len()
    }

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
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(v))));
        self.nm.push(n.to_string());
    }

    fn dup(&mut self, n: &str) {
        (self.e)(StackOp::Dup);
        self.nm.push(n.to_string());
    }

    fn drop(&mut self) {
        (self.e)(StackOp::Drop);
        if !self.nm.is_empty() {
            self.nm.pop();
        }
    }

    fn nip(&mut self) {
        (self.e)(StackOp::Nip);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.remove(len - 2);
        }
    }

    fn over(&mut self, n: &str) {
        (self.e)(StackOp::Over);
        self.nm.push(n.to_string());
    }

    fn swap(&mut self) {
        (self.e)(StackOp::Swap);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.swap(len - 1, len - 2);
        }
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
        if d == 0 {
            return;
        }
        if d == 1 {
            self.swap();
            return;
        }
        if d == 2 {
            self.rot();
            return;
        }
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_ROLL".into()));
        self.nm.pop(); // pop the push
        let idx = self.nm.len() - 1 - d;
        let r = self.nm.remove(idx);
        self.nm.push(r);
    }

    fn pick(&mut self, d: usize, n: &str) {
        if d == 0 {
            self.dup(n);
            return;
        }
        if d == 1 {
            self.over(n);
            return;
        }
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
        self.nm.push(String::new());
        (self.e)(StackOp::Opcode("OP_PICK".into()));
        self.nm.pop(); // pop the push
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
        if !self.nm.is_empty() {
            self.nm.pop();
        }
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

    /// Emit raw opcodes; tracker only records net stack effect.
    fn raw_block(
        &mut self,
        consume: &[&str],
        produce: Option<&str>,
        f: impl FnOnce(&mut dyn FnMut(StackOp)),
    ) {
        for _ in consume {
            if !self.nm.is_empty() {
                self.nm.pop();
            }
        }
        f(self.e);
        if let Some(p) = produce {
            self.nm.push(p.to_string());
        }
    }

    /// Emit if/else with tracked stack effect.
    fn emit_if(
        &mut self,
        cond_name: &str,
        then_fn: impl FnOnce(&mut dyn FnMut(StackOp)),
        else_fn: impl FnOnce(&mut dyn FnMut(StackOp)),
        result_name: Option<&str>,
    ) {
        self.to_top(cond_name);
        self.nm.pop(); // condition consumed
        let then_ops = collect_ops(then_fn);
        let else_ops = collect_ops(else_fn);
        (self.e)(StackOp::If {
            then_ops,
            else_ops,
        });
        if let Some(rn) = result_name {
            self.nm.push(rn.to_string());
        }
    }
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

/// secp256k1 field prime p as a Bitcoin script number (little-endian sign-magnitude).
/// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
/// Big-endian bytes [0..31]:
///   [ff]*27, fe, ff, ff, fc, 2f
/// Reversed to LE (byte 31 first):
///   2f, fc, ff, ff, fe, [ff]*27
/// MSB (0xff) has bit 7 set, so we append a 0x00 sign byte to keep it positive.
const FIELD_P_SCRIPT_NUM: [u8; 33] = [
    0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
];

/// Push the field prime p onto the stack as a script number.
fn push_field_p(t: &mut ECTracker, name: &str) {
    // Push p as pre-encoded script number bytes — equivalent to pushInt(FIELD_P)
    // in the TS implementation, but using bytes since FIELD_P exceeds i128.
    t.push_bytes(name, FIELD_P_SCRIPT_NUM.to_vec());
}

/// fieldMod: reduce TOS mod p, ensure non-negative.
/// Expects `a_name` to be on the tracker stack.
fn field_mod(t: &mut ECTracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    push_field_p(t, "_fmod_p");
    // (a % p + p) % p
    t.raw_block(&[a_name, "_fmod_p"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_2DUP".into())); // a p a p
        e(StackOp::Opcode("OP_MOD".into()));   // a p (a%p)
        e(StackOp::Rot);                        // p (a%p) a
        e(StackOp::Drop);                       // p (a%p)
        e(StackOp::Over);                       // p (a%p) p
        e(StackOp::Opcode("OP_ADD".into()));    // p (a%p+p)
        e(StackOp::Swap);                       // (a%p+p) p
        e(StackOp::Opcode("OP_MOD".into()));    // ((a%p+p)%p)
    });
}

/// fieldAdd: (a + b) mod p.
fn field_add(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fadd_sum"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    field_mod(t, "_fadd_sum", result_name);
}

/// fieldSub: (a - b) mod p (non-negative).
fn field_sub(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fsub_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    field_mod(t, "_fsub_diff", result_name);
}

/// fieldMul: (a * b) mod p.
fn field_mul(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fmul_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    field_mod(t, "_fmul_prod", result_name);
}

/// fieldMulConst: (a * c) mod p where c is a small constant.
fn field_mul_const(t: &mut ECTracker, a_name: &str, c: i128, result_name: &str) {
    t.to_top(a_name);
    t.raw_block(&[a_name], Some("_fmc_prod"), |e| {
        if c == 2 {
            // Use OP_2MUL (single opcode, no push needed)
            e(StackOp::Opcode("OP_2MUL".into()));
        } else {
            e(StackOp::Push(PushValue::Int(BigInt::from(c))));
            e(StackOp::Opcode("OP_MUL".into()));
        }
    });
    field_mod(t, "_fmc_prod", result_name);
}

/// fieldSqr: (a * a) mod p.
fn field_sqr(t: &mut ECTracker, a_name: &str, result_name: &str) {
    t.copy_to_top(a_name, "_fsqr_copy");
    field_mul(t, a_name, "_fsqr_copy", result_name);
}

/// fieldInv: a^(p-2) mod p via square-and-multiply.
/// Consumes a_name from the tracker.
fn field_inv(t: &mut ECTracker, a_name: &str, result_name: &str) {
    // p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
    // Bits 255..32: 224 bits, all 1 except bit 32 which is 0
    // Bits 31..0: 0xFFFFFC2D

    // Start: result = a (bit 255 = 1)
    t.copy_to_top(a_name, "_inv_r");
    // Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
    for _i in 0..222 {
        field_sqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");
        t.copy_to_top(a_name, "_inv_a");
        field_mul(t, "_inv_r", "_inv_a", "_inv_m");
        t.rename("_inv_r");
    }
    // Bit 32 is 0: square only (no multiply)
    field_sqr(t, "_inv_r", "_inv_r2");
    t.rename("_inv_r");
    // Bits 31 down to 0 of p-2
    let low_bits = FIELD_P_MINUS_2_LOW32;
    for i in (0..=31).rev() {
        field_sqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");
        if (low_bits >> i) & 1 != 0 {
            t.copy_to_top(a_name, "_inv_a");
            field_mul(t, "_inv_r", "_inv_a", "_inv_m");
            t.rename("_inv_r");
        }
    }
    // Clean up original input and rename result
    t.to_top(a_name);
    t.drop();
    t.to_top("_inv_r");
    t.rename(result_name);
}

// ===========================================================================
// Point decompose / compose
// ===========================================================================

/// CL-BUG-095 — length gate for a `Point` argument, ABORTING form.
///
/// A `Point` is DEFINED as exactly `want` bytes (x ‖ y, big-endian, no prefix).
/// Nothing checked that: `Point` carries no width in the builtin table, and
/// every one of these values arrives as an unlock argument, so the blob is
/// attacker-sized. Surplus bytes were then silently DISCARDED, because
/// `decompose_point` splits at the coordinate width and `emit_reverse_32`
/// reverses exactly 32 bytes and drops whatever is left over — so
/// `ecOnCurve(G ‖ 0xff)` returned TRUE and `ecEncodeCompressed` took its parity
/// bit from the surplus.
///
/// This is NOT a new failure channel. An UNDER-length point already aborted, by
/// accident: `OP_SPLIT` runs off the end of the value. The gate makes the same
/// outcome explicit, and extends it to the over-length case that used to pass.
///
/// Aborting is right for every Point consumer that produces a VALUE and has no
/// error channel to report through — `ecAdd`, `ecMul`, `ecNegate`, `ecPointX`,
/// `ecPointY`, `ecEncodeCompressed`. There is no correct value to return for a
/// blob that is not a point. The PREDICATES (`ecOnCurve` and friends) use
/// `emit_point_length_gate` below instead, because for them "no" is an answer.
pub fn emit_point_len_verify(e: &mut dyn FnMut(StackOp), want: usize) {
    e(StackOp::Opcode("OP_SIZE".into()));
    e(StackOp::Push(PushValue::Int(BigInt::from(want as i128))));
    e(StackOp::Opcode("OP_NUMEQUALVERIFY".into()));
}

/// CL-BUG-095 — length gate for a `Point` argument, CLAMPING form: leaves
/// `[flag, clamped]`, where `clamped` is the value forced to exactly `want`
/// bytes (`v ‖ 00*want` split at `want`, tail dropped) and `flag` is
/// `OP_SIZE(v) == want`.
///
/// Same shape, and the same reasoning, as `c_emit_length_gate` in
/// p256_p384.rs: the clamp exists so the gate can stay a FLAG. It is used by
/// the on-curve predicates, whose whole job is to answer "is this an acceptable
/// point?" over untrusted bytes — and for a wrong-length blob the correct answer
/// is `false`, not an aborted script. Aborting would break
/// `if (ecOnCurve(p)) { … } else { … }`, which is the exact idiom this module's
/// own comments tell contract authors to write. The caller ANDs `flag` into its
/// boolean result, so whatever the clamped bytes happen to compute can never
/// make a wrong-length point certify as on-curve.
///
/// Branch-free: the emitted op sequence, and the tracker's static stack model,
/// are identical for every input length.
fn emit_point_length_gate(t: &mut ECTracker, name: &str, want: usize, flag_name: &str) {
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
    t.nm.push(flag_name.to_string());
    t.nm.push(name.to_string());
}

/// Decompose 64-byte Point -> (x_num, y_num) on stack.
/// Consumes pointName, produces xName and yName.
fn decompose_point(t: &mut ECTracker, point_name: &str, x_name: &str, y_name: &str) {
    t.to_top(point_name);
    // OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top) — but only for
    // a value that really is 64 bytes. CL-BUG-095: gate the width first, here,
    // so every consumer that decomposes a Point inherits the check.
    t.raw_block(&[point_name], None, |e| {
        emit_point_len_verify(e, 64);
        e(StackOp::Push(PushValue::Int(BigInt::from(32))));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    // Manually track the two new items
    t.nm.push("_dp_xb".to_string());
    t.nm.push("_dp_yb".to_string());

    // Convert y_bytes (on top) to num
    // Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
    t.raw_block(&["_dp_yb"], Some(y_name), |e| {
        emit_reverse_32(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Convert x_bytes to num
    t.to_top("_dp_xb");
    t.raw_block(&["_dp_xb"], Some(x_name), |e| {
        emit_reverse_32(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });

    // Stack: [yName, xName] — swap to standard order [xName, yName]
    t.swap();
}

/// Compose (x_num, y_num) -> 64-byte Point.
/// Consumes xName and yName, produces resultName.
fn compose_point(t: &mut ECTracker, x_name: &str, y_name: &str, result_name: &str) {
    // Convert x to 32-byte big-endian
    // Use NUM2BIN(33) to accommodate the sign byte, then drop the last byte
    t.to_top(x_name);
    t.raw_block(&[x_name], Some("_cp_xb"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(33))));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        // Drop the sign byte (last byte) — split at 32, keep left
        e(StackOp::Push(PushValue::Int(BigInt::from(32))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        emit_reverse_32(e);
    });

    // Convert y to 32-byte big-endian
    t.to_top(y_name);
    t.raw_block(&[y_name], Some("_cp_yb"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(33))));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(32))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        emit_reverse_32(e);
    });

    // Cat: x_be || y_be (x is below y after the two to_top calls)
    t.to_top("_cp_xb");
    t.to_top("_cp_yb");
    t.raw_block(&["_cp_xb", "_cp_yb"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_CAT".into()));
    });
}

/// Emit inline byte reversal for a 32-byte value on TOS.
/// After: reversed 32-byte value on TOS.
pub fn emit_reverse_32(e: &mut dyn FnMut(StackOp)) {
    // Push empty accumulator, swap with data
    e(StackOp::Opcode("OP_0".into()));
    e(StackOp::Swap);
    // 32 iterations: peel first byte, prepend to accumulator
    for _i in 0..32 {
        // Stack: [accum, remaining]
        e(StackOp::Push(PushValue::Int(BigInt::from(1))));
        e(StackOp::Opcode("OP_SPLIT".into()));
        // Stack: [accum, byte0, rest]
        e(StackOp::Rot);
        // Stack: [byte0, rest, accum]
        e(StackOp::Rot);
        // Stack: [rest, accum, byte0]
        e(StackOp::Swap);
        // Stack: [rest, byte0, accum]
        e(StackOp::Opcode("OP_CAT".into()));
        // Stack: [rest, byte0||accum]
        e(StackOp::Swap);
        // Stack: [byte0||accum, rest]
    }
    // Stack: [reversed, empty]
    e(StackOp::Drop);
}

// ===========================================================================
// Affine point addition (for ecAdd)
// ===========================================================================

/// Affine point addition: expects px, py, qx, qy on tracker.
/// Produces rx, ry. Consumes all four inputs.
fn affine_add(t: &mut ECTracker) {
    // The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
    // denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
    // Without this, ecAdd(P, P) silently produced a wrong point, so every
    // contract that doubled deployed an unspendable script.
    //
    // Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR
    // are selected and the single expensive field_inv still runs exactly once.
    // rx and ry below are already correct for doubling.
    //
    //   cond = (px == qx) AND (py == qy)
    //   num  = cond ? 3*px^2 : (qy - py)
    //   den  = cond ? 2*py   : (qx - px)
    //
    // selected as `b + cond*(a - b)`, which needs no branch and keeps the
    // emitted op sequence identical on both paths.
    //
    // THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
    // sends it down the tangent path and returns 2P — an on-curve, entirely
    // plausible, WRONG point. Before the doubling fix the chord path ran there,
    // divided by zero (field_inv is Fermat, inv(0) = 0) and produced an
    // OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))` — the idiom this
    // codegen tells authors to write — happened to reject it. Selecting on px
    // alone would have silently disarmed that.
    //
    // P + (-P) is the point at infinity, which affine x||y cannot represent.
    // This codegen already has a representation for O: the ALL-ZERO blob, which
    // is what `ecMul(P, 0n)` returns and what the `ec-mulgen-linear` rewrite in
    // optimizer/ec-rules.json produces for k1 + k2 ≡ 0 (mod n). So return that,
    // by masking the result with `notinf = NOT(px == qx AND NOT cond)`:
    //
    //   - it agrees with the rewrite, so the same source cannot give two
    //     answers depending on whether the optimizer fired;
    //   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects
    //     it and the idiom above works again;
    //   - it adds no failure channel to what is a pure value-producing
    //     expression, the same reason emit_scalar_reduce reduces instead of
    //     rejecting.
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
    // notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
    // points are not equal, i.e. exactly the P == -Q case.
    t.to_top("_xeq");
    t.copy_to_top("_cond", "_cond_c");
    t.raw_block(&["_xeq", "_cond_c"], Some("_notinf"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
        e(StackOp::Opcode("OP_NOT".into()));
    });

    // chord numerator / denominator
    t.copy_to_top("qy", "_qy1");
    t.copy_to_top("py", "_py1");
    field_sub(t, "_qy1", "_py1", "_num_chord");
    t.copy_to_top("qx", "_qx1");
    t.copy_to_top("px", "_px1");
    field_sub(t, "_qx1", "_px1", "_den_chord");

    // tangent numerator / denominator: 3*px^2 and 2*py
    t.copy_to_top("px", "_px_t");
    field_sqr(t, "_px_t", "_px_sq");
    field_mul_const(t, "_px_sq", 3, "_num_tan");
    t.copy_to_top("py", "_py_t");
    field_mul_const(t, "_py_t", 2, "_den_tan");

    // num = num_chord + cond*(num_tan - num_chord)
    t.copy_to_top("_num_chord", "_num_chord_c");
    field_sub(t, "_num_tan", "_num_chord_c", "_num_diff");
    t.copy_to_top("_cond", "_cond_n");
    field_mul(t, "_num_diff", "_cond_n", "_num_sel");
    field_add(t, "_num_chord", "_num_sel", "_s_num");

    // den = den_chord + cond*(den_tan - den_chord)
    t.copy_to_top("_den_chord", "_den_chord_c");
    field_sub(t, "_den_tan", "_den_chord_c", "_den_diff");
    t.to_top("_cond");
    t.rename("_cond_d");
    field_mul(t, "_den_diff", "_cond_d", "_den_sel");
    field_add(t, "_den_chord", "_den_sel", "_s_den");

    // s = s_num / s_den mod p
    field_inv(t, "_s_den", "_s_den_inv");
    field_mul(t, "_s_num", "_s_den_inv", "_s");

    // rx = s^2 - px - qx mod p
    t.copy_to_top("_s", "_s_keep");
    field_sqr(t, "_s", "_s2");
    t.copy_to_top("px", "_px2");
    field_sub(t, "_s2", "_px2", "_rx1");
    t.copy_to_top("qx", "_qx2");
    field_sub(t, "_rx1", "_qx2", "rx");

    // ry = s * (px - rx) - py mod p
    t.copy_to_top("px", "_px3");
    t.copy_to_top("rx", "_rx2");
    field_sub(t, "_px3", "_rx2", "_px_rx");
    field_mul(t, "_s_keep", "_px_rx", "_s_px_rx");
    t.copy_to_top("py", "_py2");
    field_sub(t, "_s_px_rx", "_py2", "ry");

    // CL-BUG-096: select over the infinity operands and the P == -Q case, and
    // consume px/py/qx/qy in doing so. This subsumes the standalone `notinf`
    // mask that used to live here. See emit_affine_infinity_select.
    emit_affine_infinity_select(t);
}

// ===========================================================================
// CL-BUG-096 — infinity-operand select, shared by all three curves
// ===========================================================================

/// The subset of the tracker surface `emit_affine_infinity_select` needs.
///
/// `ec.rs` and `p256_p384.rs` each carry their own private `ECTracker` (the
/// duplication predates this fix), so the one shared implementation reaches
/// both through this trait rather than being written twice. The helper only
/// ever emits plain opcodes, so `sel_raw_ops` takes a code list instead of the
/// general `raw_block` closure.
pub trait AffineSelectTracker {
    fn sel_copy_to_top(&mut self, name: &str, alias: &str);
    fn sel_push_int(&mut self, name: &str, v: i128);
    fn sel_to_top(&mut self, name: &str);
    fn sel_raw_ops(&mut self, consume: &[&str], produce: &str, codes: &[&str]);
}

impl<'a> AffineSelectTracker for ECTracker<'a> {
    fn sel_copy_to_top(&mut self, name: &str, alias: &str) {
        let d = self.find_depth(name);
        self.pick(d, alias);
    }
    fn sel_push_int(&mut self, name: &str, v: i128) {
        self.push_int(name, v);
    }
    fn sel_to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        self.roll(d);
    }
    fn sel_raw_ops(&mut self, consume: &[&str], produce: &str, codes: &[&str]) {
        self.raw_block(consume, Some(produce), |e| {
            for c in codes {
                e(StackOp::Opcode((*c).into()));
            }
        });
    }
}

/// CL-BUG-096 — the infinity-operand case of affine addition, shared by
/// secp256k1 and the two NIST curves because it is pure integer masking and
/// touches no field parameter.
///
/// The group law has an identity, and this codegen has a representation for it:
/// the ALL-ZERO blob. It is not a theoretical value — the codegen MANUFACTURES
/// it, from `ecMul(P, k)` whenever k ≡ 0 (mod n), from affine_add's own P + (−P)
/// masking, and from the `ec-mul-zero` / `ec-add-negate-cancel` rewrites in
/// optimizer/ec-rules.json. `affine_add` nonetheless had no case for it: fed
/// (G, O) it took the chord path with s = Gy/Gx and returned an off-curve blob
/// from a script that SUCCEEDED.
///
/// And the always-on EC optimizer already believed the right answer:
/// `ec-add-identity-right` / `-left` rewrite `ecAdd($x, INFINITY)` to `$x`. So
/// the same source meant "P" with the optimizer on and "garbage" with it off.
/// Fixing the adder rather than deleting the two rules is the only option that
/// works, because the rules cannot see a zero scalar that only exists at
/// runtime — deleting them would leave the runtime path just as wrong and
/// rewrite nothing.
///
/// Branch-free, in the style the rest of this adder uses. Exactly one of the
/// three masks is 1 and the other two are 0, so the sum selects one term:
///
///   pinf = (px == 0) AND (py == 0)          P is O
///   qinf = (qx == 0) AND (qy == 0)          Q is O
///   usep = qinf AND NOT pinf                -> answer is P
///   useq = pinf                             -> answer is Q  (covers O + O = O)
///   user = notinf AND NOT(pinf OR qinf)     -> answer is the computed sum
///
/// `user` folds in the pre-existing `notinf` mask (the P == −Q case), so P + (−P)
/// still yields the all-zero blob and nothing about that case changes.
///
/// Requiring BOTH coordinates to be zero is load-bearing, not belt-and-braces.
/// x = 0 has genuine curve points whenever the curve's b is a quadratic residue
/// — (0, sqrt(b)) — and testing x alone would map them to O. y = 0 has none on
/// any of these three curves (all have prime order, so no point of order 2), but
/// the conjunction makes that fact not need to be true.
///
/// Plain OP_MUL / OP_ADD with no field reduction: px, qx, rx are already in
/// [0, p) and the masks are 0 or 1, so each product and the sum are canonical.
///
/// Consumes px, py, qx, qy and the field-computed rx, ry; leaves the selected
/// rx, ry in their place.
pub fn emit_affine_infinity_select<T: AffineSelectTracker + ?Sized>(t: &mut T) {
    // pinf = (px == 0) AND (py == 0)
    t.sel_copy_to_top("px", "_px_z");
    t.sel_push_int("_zero_px", 0);
    t.sel_raw_ops(&["_px_z", "_zero_px"], "_pxz", &["OP_NUMEQUAL"]);
    t.sel_copy_to_top("py", "_py_z");
    t.sel_push_int("_zero_py", 0);
    t.sel_raw_ops(&["_py_z", "_zero_py"], "_pyz", &["OP_NUMEQUAL"]);
    t.sel_raw_ops(&["_pxz", "_pyz"], "_pinf", &["OP_BOOLAND"]);

    // qinf = (qx == 0) AND (qy == 0)
    t.sel_copy_to_top("qx", "_qx_z");
    t.sel_push_int("_zero_qx", 0);
    t.sel_raw_ops(&["_qx_z", "_zero_qx"], "_qxz", &["OP_NUMEQUAL"]);
    t.sel_copy_to_top("qy", "_qy_z");
    t.sel_push_int("_zero_qy", 0);
    t.sel_raw_ops(&["_qy_z", "_zero_qy"], "_qyz", &["OP_NUMEQUAL"]);
    t.sel_raw_ops(&["_qxz", "_qyz"], "_qinf", &["OP_BOOLAND"]);

    // usep = qinf AND NOT pinf
    t.sel_copy_to_top("_qinf", "_usep_q");
    t.sel_copy_to_top("_pinf", "_usep_p");
    t.sel_raw_ops(&["_usep_q", "_usep_p"], "_usep", &["OP_NOT", "OP_BOOLAND"]);

    // useq = pinf
    t.sel_copy_to_top("_pinf", "_useq");

    // user = notinf AND NOT(pinf OR qinf)
    t.sel_to_top("_pinf");
    t.sel_to_top("_qinf");
    t.sel_raw_ops(&["_pinf", "_qinf"], "_anyinf", &["OP_BOOLOR"]);
    t.sel_to_top("_notinf");
    t.sel_to_top("_anyinf");
    t.sel_raw_ops(&["_notinf", "_anyinf"], "_user", &["OP_NOT", "OP_BOOLAND"]);

    // rx = px*usep + qx*useq + rx*user
    t.sel_to_top("px");
    t.sel_copy_to_top("_usep", "_usep_x");
    t.sel_raw_ops(&["px", "_usep_x"], "_selx_p", &["OP_MUL"]);
    t.sel_to_top("qx");
    t.sel_copy_to_top("_useq", "_useq_x");
    t.sel_raw_ops(&["qx", "_useq_x"], "_selx_q", &["OP_MUL"]);
    t.sel_to_top("rx");
    t.sel_copy_to_top("_user", "_user_x");
    t.sel_raw_ops(&["rx", "_user_x"], "_selx_r", &["OP_MUL"]);
    t.sel_raw_ops(&["_selx_q", "_selx_r"], "_selx_qr", &["OP_ADD"]);
    t.sel_raw_ops(&["_selx_p", "_selx_qr"], "rx", &["OP_ADD"]);

    // ry = py*usep + qy*useq + ry*user  (last use of each mask: consume them)
    t.sel_to_top("py");
    t.sel_to_top("_usep");
    t.sel_raw_ops(&["py", "_usep"], "_sely_p", &["OP_MUL"]);
    t.sel_to_top("qy");
    t.sel_to_top("_useq");
    t.sel_raw_ops(&["qy", "_useq"], "_sely_q", &["OP_MUL"]);
    t.sel_to_top("ry");
    t.sel_to_top("_user");
    t.sel_raw_ops(&["ry", "_user"], "_sely_r", &["OP_MUL"]);
    t.sel_raw_ops(&["_sely_q", "_sely_r"], "_sely_qr", &["OP_ADD"]);
    t.sel_raw_ops(&["_sely_p", "_sely_qr"], "ry", &["OP_ADD"]);
}

// ===========================================================================
// Jacobian point operations (for ecMul)
// ===========================================================================

/// Jacobian point doubling (a=0 for secp256k1).
/// Expects jx, jy, jz on tracker. Replaces with updated values.
fn jacobian_double(t: &mut ECTracker) {
    // Save copies of jx, jy, jz for later use
    t.copy_to_top("jy", "_jy_save");
    t.copy_to_top("jx", "_jx_save");
    t.copy_to_top("jz", "_jz_save");

    // A = jy^2
    field_sqr(t, "jy", "_A");

    // B = 4 * jx * A
    t.copy_to_top("_A", "_A_save");
    field_mul(t, "jx", "_A", "_xA");
    t.push_int("_four", 4);
    field_mul(t, "_xA", "_four", "_B");

    // C = 8 * A^2
    field_sqr(t, "_A_save", "_A2");
    t.push_int("_eight", 8);
    field_mul(t, "_A2", "_eight", "_C");

    // D = 3 * X^2
    field_sqr(t, "_jx_save", "_x2");
    t.push_int("_three", 3);
    field_mul(t, "_x2", "_three", "_D");

    // nx = D^2 - 2*B
    t.copy_to_top("_D", "_D_save");
    t.copy_to_top("_B", "_B_save");
    field_sqr(t, "_D", "_D2");
    t.copy_to_top("_B", "_B1");
    field_mul_const(t, "_B1", 2, "_2B");
    field_sub(t, "_D2", "_2B", "_nx");

    // ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy");
    field_sub(t, "_B_save", "_nx_copy", "_B_nx");
    field_mul(t, "_D_save", "_B_nx", "_D_B_nx");
    field_sub(t, "_D_B_nx", "_C", "_ny");

    // nz = 2 * Y * Z
    field_mul(t, "_jy_save", "_jz_save", "_yz");
    field_mul_const(t, "_yz", 2, "_nz");

    // Clean up leftovers: _B (used via _B_save/_B1) and old jz (only copied, never consumed)
    t.to_top("_B"); t.drop();
    t.to_top("jz"); t.drop();
    t.to_top("_nx"); t.rename("jx");
    t.to_top("_ny"); t.rename("jy");
    t.to_top("_nz"); t.rename("jz");
}

/// Jacobian -> Affine conversion.
/// Consumes jx, jy, jz; produces rx_name, ry_name.
fn jacobian_to_affine(t: &mut ECTracker, rx_name: &str, ry_name: &str) {
    field_inv(t, "jz", "_zinv");
    t.copy_to_top("_zinv", "_zinv_keep");
    field_sqr(t, "_zinv", "_zinv2");
    t.copy_to_top("_zinv2", "_zinv2_keep");
    field_mul(t, "_zinv_keep", "_zinv2", "_zinv3");
    field_mul(t, "jx", "_zinv2_keep", rx_name);
    field_mul(t, "jy", "_zinv3", ry_name);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

/// Build Jacobian mixed-add ops for use inside OP_IF.
/// Uses an inner ECTracker to leverage field arithmetic helpers.
///
/// Stack layout: [..., ax, ay, _k, jx, jy, jz]
/// After:        [..., ax, ay, _k, jx', jy', jz']
fn build_jacobian_add_affine_inline(e: &mut dyn FnMut(StackOp), t: &ECTracker) {
    // Create inner tracker with cloned stack state
    let cloned_nm: Vec<String> = t.nm.clone();
    let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
    let mut it = ECTracker::new(&init_strs, e);
    jacobian_add_affine_body(&mut it, false);
}

/// The mixed-add itself, emitting through an ECTracker the caller owns.
///
/// `keep_hr` additionally leaves copies of H and R on the stack. They are the
/// exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
/// the Jacobian accumulator is the same curve point as the affine operand, the
/// one case these formulas cannot compute (see
/// `build_jacobian_add_or_double_inline`).
fn jacobian_add_affine_body(it: &mut ECTracker, keep_hr: bool) {
    // Save copies of values that get consumed but are needed later
    it.copy_to_top("jz", "_jz_for_z1cu");   // consumed by Z1sq, needed for Z1cu
    it.copy_to_top("jz", "_jz_for_z3");     // needed for Z3
    it.copy_to_top("jy", "_jy_for_y3");     // consumed by R, needed for Y3
    it.copy_to_top("jx", "_jx_for_u1h2");   // consumed by H, needed for U1H2

    // Z1sq = jz^2
    field_sqr(it, "jz", "_Z1sq");

    // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2");
    field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c");
    field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2");

    // S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c");
    field_mul(it, "_ay_c", "_Z1cu", "_S2");

    // H = U2 - jx
    field_sub(it, "_U2", "jx", "_H");

    // R = S2 - jy
    field_sub(it, "_S2", "jy", "_R");

    if keep_hr {
        it.copy_to_top("_H", "_H_keep");
        it.copy_to_top("_R", "_R_keep");
    }

    // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
    it.copy_to_top("_H", "_H_for_h3");
    it.copy_to_top("_H", "_H_for_z3");

    // H2 = H^2
    field_sqr(it, "_H", "_H2");

    // Save H2 for U1H2
    it.copy_to_top("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    field_mul(it, "_H_for_h3", "_H2", "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    // Save R, U1H2, H3 for Y3 computation
    it.copy_to_top("_R", "_R_for_y3");
    it.copy_to_top("_U1H2", "_U1H2_for_y3");
    it.copy_to_top("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    field_sqr(it, "_R", "_R2");
    field_sub(it, "_R2", "_H3", "_x3_tmp");
    field_mul_const(it, "_U1H2", 2, "_2U1H2");
    field_sub(it, "_x3_tmp", "_2U1H2", "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c");
    field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp");
    field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    field_sub(it, "_r_tmp", "_jy_h3", "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3");

    // Rename results to jx/jy/jz
    it.to_top("_X3"); it.rename("jx");
    it.to_top("_Y3"); it.rename("jy");
    it.to_top("_Z3"); it.rename("jz");
}

/// Branchless select of one Jacobian coordinate: `add + cond*(dbl - add)`.
/// Same shape as the numerator/denominator select in `affine_add`, so both
/// paths emit the identical op sequence and the tracker's static stack model
/// holds. Consumes `add_name`, `dbl_name` and `cond_name`.
fn select_coord(t: &mut ECTracker, add_name: &str, dbl_name: &str, cond_name: &str, result_name: &str) {
    t.copy_to_top(add_name, "_sel_add_c");
    field_sub(t, dbl_name, "_sel_add_c", "_sel_diff");
    field_mul(t, "_sel_diff", cond_name, "_sel_scaled");
    field_add(t, add_name, "_sel_scaled", result_name);
}

/// The ladder's LAST conditional step: mixed-add, but correct when the
/// accumulator already equals the point being added.
///
/// The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
/// two operands are the same curve point H = 0, so Z3 = Z1*H = 0 — the point at
/// infinity — and since `field_inv` is Fermat (inv(0) = 0), `jacobian_to_affine`
/// turns that into the ALL-ZERO point instead of 2P. `ecMul(P, 2n)` and
/// `ecMulGen(2n)` returned 64 zero bytes.
///
/// WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
/// c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
/// (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the degenerate
/// cases are exactly c_i ≡ 2 (mod n) — accumulator == P — and c_i ≡ 0 or 1
/// (mod n) — accumulator == -P or O. c_i ranges over a CONTIGUOUS interval
/// determined only by i, so this is decidable by interval arithmetic rather
/// than by sampling, and over the whole domain k ∈ [0, n-1] only two steps
/// qualify, both at i = 0:
///
///   k = 2  ->  c_0 = 3n+2 ≡ 2, odd, so the add runs: accumulator == P.  <- bug
///   k = 0  ->  c_0 = 3n   ≡ 0, odd, so the add runs: accumulator == -P,
///              true result the point at infinity, which affine coordinates
///              cannot represent; it stays the all-zero point, as before.
///
/// At i ≥ 1, c_i lies in [3n>>i, (4n-1)>>i] — the lower bound is 3n, not 3n+1,
/// because the reduce puts k = 0 in the domain — and that interval contains no
/// value ≡ 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even, so no add
/// runs.
///
/// Handling H == 0 at every one of the 257 steps would cost ~70% more script
/// bytes; handling it here costs 0.26%. The operand P is caller-supplied but
/// cannot move the exception, because the condition depends only on
/// c_i mod ord(P) and ord(P) = n for every point on the curve. Points that are
/// NOT on the curve carry no such guarantee — gate untrusted input on
/// `ecOnCurve` first.
///
/// THE ENTIRE ARGUMENT IS CONDITIONED ON k ∈ [0, n-1], which is only true
/// because `emit_ec_mul` reduces k mod n before adding 3n. That reduce landed
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
fn build_jacobian_add_or_double_inline(e: &mut dyn FnMut(StackOp), t: &ECTracker) {
    let cloned_nm: Vec<String> = t.nm.clone();
    let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
    let mut it = ECTracker::new(&init_strs, e);
    let it = &mut it;

    // Keep the pre-add accumulator: it is what must be DOUBLED in the
    // exceptional case, and the add below consumes jx/jy/jz.
    it.copy_to_top("jx", "_sx");
    it.copy_to_top("jy", "_sy");
    it.copy_to_top("jz", "_sz");

    jacobian_add_affine_body(it, true);

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

    // Move the add result aside so jacobian_double can work on jx/jy/jz again,
    // this time holding the saved accumulator.
    it.to_top("jx"); it.rename("_add_x");
    it.to_top("jy"); it.rename("_add_y");
    it.to_top("jz"); it.rename("_add_z");
    it.to_top("_sx"); it.rename("jx");
    it.to_top("_sy"); it.rename("jy");
    it.to_top("_sz"); it.rename("jz");
    jacobian_double(it);
    it.to_top("jx"); it.rename("_dbl_x");
    it.to_top("jy"); it.rename("_dbl_y");
    it.to_top("jz"); it.rename("_dbl_z");

    it.copy_to_top("_cond", "_cond_x");
    select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx");
    it.copy_to_top("_cond", "_cond_y");
    select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy");
    it.to_top("_cond"); it.rename("_cond_z");
    select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz");
}

// ===========================================================================
// Public entry points (called from stack lowerer)
// ===========================================================================

/// ecAdd: add two points.
/// Stack in: [point_a, point_b] (b on top)
/// Stack out: [result_point]
pub fn emit_ec_add(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pa", "_pb"], emit);
    decompose_point(&mut t, "_pa", "px", "py");
    decompose_point(&mut t, "_pb", "qx", "qy");
    affine_add(&mut t);
    compose_point(&mut t, "rx", "ry", "_result");
}

/// Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
///
/// OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in (-n, n);
/// the `+ n, mod n` normalises the negative half. One push of n covers both
/// reductions — the same shape as `emit_ec_mod_reduce`.
///
/// Without it, `emit_ec_mul`'s ladder is only correct while
/// 2^257 <= k + 3n < 2^258: a scalar >= ~n sets bit 258, the 257-iteration loop
/// never sees it, and the ladder returns a DIFFERENT multiple of P rather than
/// failing. Scalars are contract input, so that is attacker-chosen. Reducing
/// costs 1 push + 8 opcodes (42 bytes) against a ~429 KB script, and makes
/// k >= n, k < 0 and k = 0 all well defined.
fn emit_scalar_reduce(t: &mut ECTracker, k_name: &str, result_name: &str) {
    t.push_bytes("_n_red", CURVE_N_SCRIPT_NUM.to_vec());
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

/// ecMul: scalar multiplication P * k.
/// Stack in: [point, scalar] (scalar on top)
/// Stack out: [result_point]
///
/// Uses 256-iteration double-and-add with Jacobian coordinates.
pub fn emit_ec_mul(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt", "_k"], emit);
    // Decompose to affine base point
    decompose_point(&mut t, "_pt", "ax", "ay");

    // k' = k + 3n: guarantees bit 257 is set.
    // k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
    // is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
    // Push 3*N directly (matches TS constant-fold output).
    //
    // "k ∈ [1, n-1]" is a PRECONDITION the caller cannot enforce — the scalar is
    // usually an unlock argument — so reduce it first. See `emit_scalar_reduce`.
    t.to_top("_k");
    emit_scalar_reduce(&mut t, "_k", "_kr");
    t.push_bytes("_3n", THREE_CURVE_N_SCRIPT_NUM.to_vec());
    t.raw_block(&["_kr", "_3n"], Some("_k3n"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.rename("_k");

    // Init accumulator = P (bit 257 of k+3n is always 1)
    t.copy_to_top("ax", "jx");
    t.copy_to_top("ay", "jy");
    t.push_int("jz", 1);

    // 257 iterations: bits 256 down to 0
    for bit in (0..=256).rev() {
        // Double accumulator
        jacobian_double(&mut t);

        // Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
        t.copy_to_top("_k", "_k_copy");
        if bit == 1 {
            // Single-bit shift: OP_2DIV (no push needed)
            t.raw_block(&["_k_copy"], Some("_shifted"), |e| {
                e(StackOp::Opcode("OP_2DIV".into()));
            });
        } else if bit > 1 {
            // Multi-bit shift: push shift amount, OP_RSHIFTNUM
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

        // Move _bit to TOS and remove from tracker BEFORE generating add ops,
        // because OP_IF consumes _bit and the add ops run with _bit already gone.
        t.to_top("_bit");
        t.nm.pop(); // _bit consumed by IF
        // Only the final step can be handed two equal operands — see
        // build_jacobian_add_or_double_inline for why, and for what it costs
        // not to.
        let add_ops = collect_ops(|add_emit| {
            if bit == 0 {
                build_jacobian_add_or_double_inline(add_emit, &t);
            } else {
                build_jacobian_add_affine_inline(add_emit, &t);
            }
        });
        (t.e)(StackOp::If {
            then_ops: add_ops,
            else_ops: vec![],
        });
    }

    // Convert Jacobian to affine
    jacobian_to_affine(&mut t, "_rx", "_ry");

    // Clean up base point and scalar
    t.to_top("ax"); t.drop();
    t.to_top("ay"); t.drop();
    t.to_top("_k"); t.drop();

    // Compose result
    compose_point(&mut t, "_rx", "_ry", "_result");
}

/// ecMulGen: scalar multiplication G * k.
/// Stack in: [scalar]
/// Stack out: [result_point]
pub fn emit_ec_mul_gen(emit: &mut dyn FnMut(StackOp)) {
    // Push generator point as 64-byte blob, then delegate to ecMul
    let mut g_point = Vec::with_capacity(64);
    g_point.extend_from_slice(&GEN_X_BYTES);
    g_point.extend_from_slice(&GEN_Y_BYTES);
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_ec_mul(emit);
}

/// ecNegate: negate a point (x, p - y).
/// Stack in: [point]
/// Stack out: [negated_point]
pub fn emit_ec_negate(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);
    decompose_point(&mut t, "_pt", "_nx", "_ny");
    push_field_p(&mut t, "_fp");
    field_sub(&mut t, "_fp", "_ny", "_neg_y");
    compose_point(&mut t, "_nx", "_neg_y", "_result");
}

/// ecOnCurve: check if point is on secp256k1 (y^2 = x^3 + 7 mod p).
/// Stack in: [point]
/// Stack out: [boolean]
pub fn emit_ec_on_curve(emit: &mut dyn FnMut(StackOp)) {
    let mut t = ECTracker::new(&["_pt"], emit);

    // CL-BUG-095: width. `ecOnCurve(G ‖ 0xff)` returned TRUE — decompose_point
    // discarded the surplus byte, so 2^8 distinct blobs all certified as the
    // same point and a point's identity AS BYTES stopped being unique. Clamp and
    // remember the width, rather than abort, because this is the predicate
    // contracts are told to gate untrusted points on and it must stay total; the
    // flag is ANDed into the result at the end.
    emit_point_length_gate(&mut t, "_pt", 64, "_len_ok");

    decompose_point(&mut t, "_pt", "_x", "_y");

    // GAP-301: coordinate canonicity. `decompose_point` BIN2NUMs each coordinate
    // as an unsigned value that may be >= p; the field arithmetic below would
    // silently reduce it mod p, so a non-canonical encoding of a valid point
    // would pass. Reject it: require x < p AND y < p (coordinates are unsigned,
    // so the 0 <= lower bound holds by construction). Combined with the curve
    // equation at the end via OP_BOOLAND so ecOnCurve still returns a boolean.
    t.copy_to_top("_x", "_x_lt");
    push_field_p(&mut t, "_p_for_x");
    t.raw_block(&["_x_lt", "_p_for_x"], Some("_x_canon"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.copy_to_top("_y", "_y_lt");
    push_field_p(&mut t, "_p_for_y");
    t.raw_block(&["_y_lt", "_p_for_y"], Some("_y_canon"), |e| {
        e(StackOp::Opcode("OP_LESSTHAN".into()));
    });
    t.to_top("_x_canon");
    t.to_top("_y_canon");
    t.raw_block(&["_x_canon", "_y_canon"], Some("_canon"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });

    // lhs = y^2
    field_sqr(&mut t, "_y", "_y2");

    // rhs = x^3 + 7
    t.copy_to_top("_x", "_x_copy");
    field_sqr(&mut t, "_x", "_x2");
    field_mul(&mut t, "_x2", "_x_copy", "_x3");
    t.push_int("_seven", 7);
    field_add(&mut t, "_x3", "_seven", "_rhs");

    // Compare curve equation
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_curve_eq"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });

    // on-curve = right width AND canonical AND curve-equation
    t.to_top("_canon");
    t.to_top("_curve_eq");
    t.raw_block(&["_canon", "_curve_eq"], Some("_eq_ok"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.to_top("_len_ok");
    t.to_top("_eq_ok");
    t.raw_block(&["_len_ok", "_eq_ok"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
}

/// ecModReduce: ((value % mod) + mod) % mod
/// Stack in: [value, mod]
/// Stack out: [result]
pub fn emit_ec_mod_reduce(emit: &mut dyn FnMut(StackOp)) {
    emit(StackOp::Opcode("OP_2DUP".into()));
    emit(StackOp::Opcode("OP_MOD".into()));
    emit(StackOp::Rot);
    emit(StackOp::Drop);
    emit(StackOp::Over);
    emit(StackOp::Opcode("OP_ADD".into()));
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_MOD".into()));
}

/// ecEncodeCompressed: point -> 33-byte compressed pubkey.
/// Stack in: [point (64 bytes)]
/// Stack out: [compressed (33 bytes)]
pub fn emit_ec_encode_compressed(emit: &mut dyn FnMut(StackOp)) {
    // CL-BUG-095, and the reason this one is the sharpest edge of it: the parity
    // byte used to be taken from the blob's LAST byte (OP_SIZE 1 OP_SUB
    // OP_SPLIT), not from a fixed offset. So appending one byte FLIPPED THE SIGN
    // of the compressed encoding — the same 64-byte point compressed to 02‖x or
    // 03‖x at the caller's choice, and anything that hashes a compressed pubkey
    // (a P2PKH address, a commitment) became forgeable between the two
    // spellings. Two independent fixes, both kept: the width is verified, and
    // the parity byte is read from offset 31 of y whatever the caller sent.
    emit_point_len_verify(emit, 64);
    // Split at 32: [x_bytes, y_bytes]
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    // Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
    emit(StackOp::Push(PushValue::Int(BigInt::from(31))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Opcode("OP_NIP".into())); // drop y_head
    // Stack: [x_bytes, last_byte]
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(2))));
    emit(StackOp::Opcode("OP_MOD".into()));
    // Stack: [x_bytes, parity]
    emit(StackOp::If {
        then_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x03]))],
        else_ops: vec![StackOp::Push(PushValue::Bytes(vec![0x02]))],
    });
    // Stack: [x_bytes, prefix_byte]
    emit(StackOp::Swap);
    emit(StackOp::Opcode("OP_CAT".into()));
}

/// ecMakePoint: (x: bigint, y: bigint) -> Point.
/// Stack in: [x_num, y_num] (y on top)
/// Stack out: [point_bytes (64 bytes)]
pub fn emit_ec_make_point(emit: &mut dyn FnMut(StackOp)) {
    // Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
    emit(StackOp::Push(PushValue::Int(BigInt::from(33))));
    emit(StackOp::Opcode("OP_NUM2BIN".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Stack: [x_num, y_be]
    emit(StackOp::Swap);
    // Stack: [y_be, x_num]
    emit(StackOp::Push(PushValue::Int(BigInt::from(33))));
    emit(StackOp::Opcode("OP_NUM2BIN".into()));
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Stack: [y_be, x_be]
    emit(StackOp::Swap);
    // Stack: [x_be, y_be]
    emit(StackOp::Opcode("OP_CAT".into()));
}

/// ecPointX: extract x-coordinate from Point.
/// Stack in: [point (64 bytes)]
/// Stack out: [x as bigint]
pub fn emit_ec_point_x(emit: &mut dyn FnMut(StackOp)) {
    // CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x —
    // the split at 32 left an empty tail that `drop` happily removed. ecPointY
    // on the identical input already aborted, which is how the hole survived: a
    // short point looked "already rejected".
    emit_point_len_verify(emit, 64);
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Append 0x00 sign byte to ensure unsigned interpretation
    emit(StackOp::Push(PushValue::Bytes(vec![0x00])));
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
}

/// ecPointY: extract y-coordinate from Point.
/// Stack in: [point (64 bytes)]
/// Stack out: [y as bigint]
pub fn emit_ec_point_y(emit: &mut dyn FnMut(StackOp)) {
    emit_point_len_verify(emit, 64);
    emit(StackOp::Push(PushValue::Int(BigInt::from(32))));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Swap);
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Append 0x00 sign byte to ensure unsigned interpretation
    emit(StackOp::Push(PushValue::Bytes(vec![0x00])));
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
}

