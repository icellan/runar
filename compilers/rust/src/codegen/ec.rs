//! EC codegen — secp256k1 elliptic curve operations for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/ec-codegen.ts.
//! All helpers are self-contained.
//!
//! Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
//! Internal arithmetic uses Jacobian coordinates for scalar multiplication.

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
        (self.e)(StackOp::Push(PushValue::Int(v)));
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
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
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
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
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

/// Decompose 64-byte Point -> (x_num, y_num) on stack.
/// Consumes pointName, produces xName and yName.
fn decompose_point(t: &mut ECTracker, point_name: &str, x_name: &str, y_name: &str) {
    t.to_top(point_name);
    // OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
    t.raw_block(&[point_name], None, |e| {
        e(StackOp::Push(PushValue::Int(32)));
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
        e(StackOp::Push(PushValue::Int(33)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        // Drop the sign byte (last byte) — split at 32, keep left
        e(StackOp::Push(PushValue::Int(32)));
        e(StackOp::Opcode("OP_SPLIT".into()));
        e(StackOp::Drop);
        emit_reverse_32(e);
    });

    // Convert y to 32-byte big-endian
    t.to_top(y_name);
    t.raw_block(&[y_name], Some("_cp_yb"), |e| {
        e(StackOp::Push(PushValue::Int(33)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        e(StackOp::Push(PushValue::Int(32)));
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
fn emit_reverse_32(e: &mut dyn FnMut(StackOp)) {
    // Push empty accumulator, swap with data
    e(StackOp::Opcode("OP_0".into()));
    e(StackOp::Swap);
    // 32 iterations: peel first byte, prepend to accumulator
    for _i in 0..32 {
        // Stack: [accum, remaining]
        e(StackOp::Push(PushValue::Int(1)));
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
    // s_num = qy - py
    t.copy_to_top("qy", "_qy1");
    t.copy_to_top("py", "_py1");
    field_sub(t, "_qy1", "_py1", "_s_num");

    // s_den = qx - px
    t.copy_to_top("qx", "_qx1");
    t.copy_to_top("px", "_px1");
    field_sub(t, "_qx1", "_px1", "_s_den");

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

    // Clean up original points
    t.to_top("px"); t.drop();
    t.to_top("py"); t.drop();
    t.to_top("qx"); t.drop();
    t.to_top("qy"); t.drop();
}

// ===========================================================================
// Affine point doubling (for ecMul degenerate case)
// ===========================================================================

/// Affine point doubling: 2*P for P=(px, py).
/// Expects px, py on tracker. Consumes both, produces rx, ry.
///
/// Formula (secp256k1, a=0):
///   s = 3*px^2 / (2*py) mod p
///   rx = s^2 - 2*px mod p
///   ry = s*(px - rx) - py mod p
fn affine_double(t: &mut ECTracker) {
    // s_num = 3 * px^2
    t.copy_to_top("px", "_px_copy");
    field_sqr(t, "_px_copy", "_px2");
    t.push_int("_three_d", 3);
    field_mul(t, "_px2", "_three_d", "_s_num");

    // s_den = 2 * py
    t.copy_to_top("py", "_py_copy");
    t.push_int("_two_d", 2);
    field_mul(t, "_py_copy", "_two_d", "_s_den");

    // s = s_num / s_den mod p
    field_inv(t, "_s_den", "_s_den_inv");
    field_mul(t, "_s_num", "_s_den_inv", "_s");

    // rx = s^2 - 2*px mod p
    t.copy_to_top("_s", "_s_keep");
    field_sqr(t, "_s", "_s2");
    t.copy_to_top("px", "_px2b");
    t.push_int("_two_d2", 2);
    field_mul(t, "_px2b", "_two_d2", "_2px");
    field_sub(t, "_s2", "_2px", "rx");

    // ry = s*(px - rx) - py mod p
    t.copy_to_top("px", "_px3");
    t.copy_to_top("rx", "_rx2");
    field_sub(t, "_px3", "_rx2", "_px_rx");
    field_mul(t, "_s_keep", "_px_rx", "_s_px_rx");
    t.copy_to_top("py", "_py2d");
    field_sub(t, "_s_px_rx", "_py2d", "ry");

    // Clean up original point
    t.to_top("px"); t.drop();
    t.to_top("py"); t.drop();
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
    t.push_int("_two1", 2);
    field_mul(t, "_B1", "_two1", "_2B");
    field_sub(t, "_D2", "_2B", "_nx");

    // ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy");
    field_sub(t, "_B_save", "_nx_copy", "_B_nx");
    field_mul(t, "_D_save", "_B_nx", "_D_B_nx");
    field_sub(t, "_D_B_nx", "_C", "_ny");

    // nz = 2 * Y * Z
    field_mul(t, "_jy_save", "_jz_save", "_yz");
    t.push_int("_two2", 2);
    field_mul(t, "_yz", "_two2", "_nz");

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

    // Save copies of values that get consumed but are needed later
    it.copy_to_top("jz", "_jz_for_z1cu");   // consumed by Z1sq, needed for Z1cu
    it.copy_to_top("jz", "_jz_for_z3");     // needed for Z3
    it.copy_to_top("jy", "_jy_for_y3");     // consumed by R, needed for Y3
    it.copy_to_top("jx", "_jx_for_u1h2");   // consumed by H, needed for U1H2

    // Z1sq = jz^2
    field_sqr(&mut it, "jz", "_Z1sq");

    // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2");
    field_mul(&mut it, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c");
    field_mul(&mut it, "_ax_c", "_Z1sq_for_u2", "_U2");

    // S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c");
    field_mul(&mut it, "_ay_c", "_Z1cu", "_S2");

    // H = U2 - jx
    field_sub(&mut it, "_U2", "jx", "_H");

    // R = S2 - jy
    field_sub(&mut it, "_S2", "jy", "_R");

    // Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
    it.copy_to_top("_H", "_H_for_h3");
    it.copy_to_top("_H", "_H_for_z3");

    // H2 = H^2
    field_sqr(&mut it, "_H", "_H2");

    // Save H2 for U1H2
    it.copy_to_top("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    field_mul(&mut it, "_H_for_h3", "_H2", "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    field_mul(&mut it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    // Save R, U1H2, H3 for Y3 computation
    it.copy_to_top("_R", "_R_for_y3");
    it.copy_to_top("_U1H2", "_U1H2_for_y3");
    it.copy_to_top("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    field_sqr(&mut it, "_R", "_R2");
    field_sub(&mut it, "_R2", "_H3", "_x3_tmp");
    it.push_int("_two", 2);
    field_mul(&mut it, "_U1H2", "_two", "_2U1H2");
    field_sub(&mut it, "_x3_tmp", "_2U1H2", "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c");
    field_sub(&mut it, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    field_mul(&mut it, "_R_for_y3", "_u_minus_x", "_r_tmp");
    field_mul(&mut it, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    field_sub(&mut it, "_r_tmp", "_jy_h3", "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    field_mul(&mut it, "_jz_for_z3", "_H_for_z3", "_Z3");

    // Rename results to jx/jy/jz
    it.to_top("_X3"); it.rename("jx");
    it.to_top("_Y3"); it.rename("jy");
    it.to_top("_Z3"); it.rename("jz");
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
    t.to_top("_k");
    t.push_bytes("_3n", THREE_CURVE_N_SCRIPT_NUM.to_vec());
    t.raw_block(&["_k", "_3n"], Some("_k3n"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.rename("_k");

    // Pre-compute 2*P via affine doubling and store on altstack.
    // This handles the degenerate case where the mixed Jacobian-affine addition
    // hits P+P (H=0 -> Z3=0), which happens for ecMul(P, 2).
    // Computing OUTSIDE the IF/ELSE avoids issues with field ops inside ELSE branches.
    // Stack: [ax, ay, _k]
    t.copy_to_top("ax", "px");
    t.copy_to_top("ay", "py");
    affine_double(&mut t);
    // Stack: [ax, ay, _k, rx, ry] -- ry on top
    // Push ry first, then rx to altstack so LIFO pop gives rx then ry
    t.to_alt(); // ry -> altstack
    t.to_alt(); // rx -> altstack
    // Stack: [ax, ay, _k], Altstack: [ry_2p, rx_2p] (top = rx_2p)

    // Init accumulator = P (bit 257 of k+3n is always 1)
    t.copy_to_top("ax", "jx");
    t.copy_to_top("ay", "jy");
    t.push_int("jz", 1);

    // 257 iterations: bits 256 down to 0
    for bit in (0..=256).rev() {
        // Double accumulator
        jacobian_double(&mut t);

        // Extract bit: (k >> bit) & 1, using OP_DIV for right-shift
        t.copy_to_top("_k", "_k_copy");
        if bit > 0 {
            // divisor = 1 << bit — use Int for small values (matches TS OP_1..OP_16),
            // script-number-encoded bytes for larger values that exceed i128.
            if bit <= 126 {
                t.push_int("_div", 1i128 << bit);
            } else {
                let divisor_bytes = script_number_pow2(bit);
                t.push_bytes("_div", divisor_bytes);
            }
            t.raw_block(&["_k_copy", "_div"], Some("_shifted"), |e| {
                e(StackOp::Opcode("OP_DIV".into()));
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
        let add_ops = collect_ops(|add_emit| {
            build_jacobian_add_affine_inline(add_emit, &t);
        });
        (t.e)(StackOp::If {
            then_ops: add_ops,
            else_ops: vec![],
        });
    }

    // Check for degenerate case: Z=0 means the mixed addition hit P+P.
    // Stack: [ax, ay, _k, jx, jy, jz], Altstack: [ry_2p, rx_2p] (top = rx_2p)
    t.copy_to_top("jz", "_z_chk");
    t.to_top("_z_chk");
    t.nm.pop(); // consumed by IF

    // Normal path (Z!=0): Jacobian to affine, discard altstack 2P values
    let normal_ops = collect_ops(|normal_emit| {
        let cloned_nm: Vec<String> = t.nm.clone();
        let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
        let mut nt = ECTracker::new(&init_strs, normal_emit);
        jacobian_to_affine(&mut nt, "_rx", "_ry");
        // Discard pre-computed 2P from altstack (LIFO: rx_2p first, then ry_2p)
        nt.from_alt("_alt_rx_d"); nt.to_top("_alt_rx_d"); nt.drop();
        nt.from_alt("_alt_ry_d"); nt.to_top("_alt_ry_d"); nt.drop();
    });

    // Degenerate path (Z=0): drop jx,jy,jz, retrieve 2P from altstack
    let deg_ops = collect_ops(|deg_emit| {
        let cloned_nm: Vec<String> = t.nm.clone();
        let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
        let mut dt = ECTracker::new(&init_strs, deg_emit);
        dt.to_top("jz"); dt.drop();
        dt.to_top("jy"); dt.drop();
        dt.to_top("jx"); dt.drop();
        // Retrieve pre-computed 2P from altstack (LIFO: rx_2p first, then ry_2p)
        dt.from_alt("_rx");
        dt.from_alt("_ry");
    });

    (t.e)(StackOp::If {
        then_ops: normal_ops,
        else_ops: deg_ops,
    });
    // Both branches leave: [ax, ay, _k, _rx, _ry]
    t.nm.pop(); // remove jz (consumed/dropped)
    t.nm.pop(); // remove jy (consumed/dropped)
    t.nm.pop(); // remove jx (consumed/dropped)
    t.nm.push("_rx".to_string());
    t.nm.push("_ry".to_string());

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
    decompose_point(&mut t, "_pt", "_x", "_y");

    // lhs = y^2
    field_sqr(&mut t, "_y", "_y2");

    // rhs = x^3 + 7
    t.copy_to_top("_x", "_x_copy");
    field_sqr(&mut t, "_x", "_x2");
    field_mul(&mut t, "_x2", "_x_copy", "_x3");
    t.push_int("_seven", 7);
    field_add(&mut t, "_x3", "_seven", "_rhs");

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
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

/// ecMakePoint: (x: bigint, y: bigint) -> Point.
/// Stack in: [x_num, y_num] (y on top)
/// Stack out: [point_bytes (64 bytes)]
pub fn emit_ec_make_point(emit: &mut dyn FnMut(StackOp)) {
    // Convert y to 32 bytes big-endian (NUM2BIN(33) to handle sign byte, then take first 32)
    emit(StackOp::Push(PushValue::Int(33)));
    emit(StackOp::Opcode("OP_NUM2BIN".into()));
    emit(StackOp::Push(PushValue::Int(32)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Stack: [x_num, y_be]
    emit(StackOp::Swap);
    // Stack: [y_be, x_num]
    emit(StackOp::Push(PushValue::Int(33)));
    emit(StackOp::Opcode("OP_NUM2BIN".into()));
    emit(StackOp::Push(PushValue::Int(32)));
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
    emit(StackOp::Push(PushValue::Int(32)));
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
    emit(StackOp::Push(PushValue::Int(32)));
    emit(StackOp::Opcode("OP_SPLIT".into()));
    emit(StackOp::Swap);
    emit(StackOp::Drop);
    emit_reverse_32(emit);
    // Append 0x00 sign byte to ensure unsigned interpretation
    emit(StackOp::Push(PushValue::Bytes(vec![0x00])));
    emit(StackOp::Opcode("OP_CAT".into()));
    emit(StackOp::Opcode("OP_BIN2NUM".into()));
}

// ===========================================================================
// Utility: encode 1 << n as a Bitcoin script number
// ===========================================================================

/// Encode (1 << n) as a Bitcoin Script number (little-endian sign-magnitude).
/// This matches what the TS emitter produces for `PushValue::Int(bigint)`.
/// Used for the scalar bit extraction divisor in ecMul where shift amounts
/// can exceed i128 range.
fn script_number_pow2(n: usize) -> Vec<u8> {
    // Script number for 2^n:
    // - The value 2^n has bit n set and all other bits zero.
    // - In little-endian: byte index = n/8, bit within byte = n%8.
    // - Need (n/8)+1 bytes minimum.
    // - If the highest bit of the last byte is set (bit 7), we need an
    //   extra 0x00 byte for the sign (positive).
    let byte_idx = n / 8;
    let bit_pos = n % 8;
    let min_len = byte_idx + 1;
    let needs_sign_byte = bit_pos == 7;
    let total_len = if needs_sign_byte { min_len + 1 } else { min_len };

    let mut bytes = vec![0u8; total_len];
    bytes[byte_idx] = 1 << bit_pos;
    // If bit_pos == 7, the high bit of the last data byte is set,
    // and we've already added a 0x00 sign byte at the end.
    bytes
}
