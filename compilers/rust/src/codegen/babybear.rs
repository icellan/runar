//! Baby Bear field arithmetic codegen -- Baby Bear prime field operations for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/babybear-codegen.ts.
//! Follows the ec.rs pattern: self-contained module imported by stack.rs.
//! Uses a BBTracker for named stack state tracking.
//!
//! Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
//! Used by SP1 STARK proofs (FRI verification).
//!
//! All values fit in a single BSV script number (31-bit prime).
//! No multi-limb arithmetic needed.

use num_bigint::BigInt;
use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// Baby Bear field prime p = 2^31 - 2^27 + 1
const BB_P: i64 = 2013265921;
/// p - 2, used for Fermat's little theorem modular inverse
const BB_P_MINUS_2: i64 = BB_P - 2;
/// Quartic extension irreducible polynomial coefficient W = 11
const BB_W: i64 = 11;

// ===========================================================================
// BBTracker -- named stack state tracker (mirrors ECTracker)
// ===========================================================================

struct BBTracker<'a> {
    nm: Vec<String>,
    e: &'a mut dyn FnMut(StackOp),
}

#[allow(dead_code)]
impl<'a> BBTracker<'a> {
    fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        BBTracker {
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
        panic!("BBTracker: '{}' not on stack {:?}", name, self.nm);
    }

    fn push_int(&mut self, n: &str, v: i64) {
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(v as i128))));
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

    fn pick(&mut self, depth: usize, n: &str) {
        if depth == 0 { self.dup(n); return; }
        if depth == 1 { self.over(n); return; }
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(depth as i128))));
        self.nm.push(String::new());
        (self.e)(StackOp::Pick { depth });
        self.nm.pop();
        self.nm.push(n.to_string());
    }

    fn roll(&mut self, d: usize) {
        if d == 0 { return; }
        if d == 1 { self.swap(); return; }
        if d == 2 { self.rot(); return; }
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
        self.nm.push(String::new());
        (self.e)(StackOp::Roll { depth: d });
        self.nm.pop();
        let idx = self.nm.len() - 1 - d;
        let item = self.nm.remove(idx);
        self.nm.push(item);
    }

    /// Bring a named value to stack top (non-consuming copy via PICK).
    fn copy_to_top(&mut self, name: &str, new_name: &str) {
        self.pick(self.find_depth(name), new_name);
    }

    /// Bring a named value to stack top (consuming via ROLL).
    fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        if d == 0 {
            return;
        }
        self.roll(d);
    }

    /// Rename the top-of-stack entry.
    fn rename(&mut self, new_name: &str) {
        if let Some(last) = self.nm.last_mut() {
            *last = new_name.to_string();
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
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/// fieldMod: ensure value is in [0, p).
/// For Baby Bear, inputs from add/mul are already non-negative, but sub can produce negatives.
/// Pattern: (a % p + p) % p
fn field_mod(t: &mut BBTracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.raw_block(&[a_name], Some(result_name), |e| {
        // (a % p + p) % p -- handles negative values from sub
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_MOD".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_ADD".into()));
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

/// fieldAdd: (a + b) mod p
fn field_add(t: &mut BBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_bb_add"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    t.to_top("_bb_add");
    t.raw_block(&["_bb_add"], Some(result_name), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

/// fieldSub: (a - b) mod p (non-negative)
fn field_sub(t: &mut BBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_bb_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    // Difference can be negative, need full mod-reduce
    field_mod(t, "_bb_diff", result_name);
}

/// fieldMul: (a * b) mod p
fn field_mul(t: &mut BBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_bb_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    // Product of two non-negative values is non-negative, simple OP_MOD
    t.to_top("_bb_prod");
    t.raw_block(&["_bb_prod"], Some(result_name), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

/// fieldSqr: (a * a) mod p
fn field_sqr(t: &mut BBTracker, a_name: &str, result_name: &str) {
    t.copy_to_top(a_name, "_bb_sqr_copy");
    field_mul(t, a_name, "_bb_sqr_copy", result_name);
}

/// fieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
/// p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
/// 31 bits, popcount 28.
/// ~30 squarings + ~27 multiplies = ~57 compound operations.
fn field_inv(t: &mut BBTracker, a_name: &str, result_name: &str) {
    // Binary representation of p-2 = 2013265919:
    // Bit 30 (MSB): 1
    // Bits 29..28: 11
    // Bit 27: 0
    // Bits 26..0: all 1's (27 ones)

    // Start: result = a (for MSB bit 30 = 1)
    t.copy_to_top(a_name, "_inv_r");

    // Process bits 29 down to 0 (30 bits)
    let p_minus_2 = BB_P_MINUS_2;
    for i in (0..=29).rev() {
        // Always square
        field_sqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");

        // Multiply if bit is set
        if (p_minus_2 >> i) & 1 == 1 {
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

/// fieldMulConst: (a * c) mod p where c is a compile-time constant
fn field_mul_const(t: &mut BBTracker, a_name: &str, c: i64, result_name: &str) {
    t.to_top(a_name);
    t.raw_block(&[a_name], Some("_bb_mc"), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(c as i128))));
        e(StackOp::Opcode("OP_MUL".into()));
    });
    t.to_top("_bb_mc");
    t.raw_block(&["_bb_mc"], Some(result_name), |e| {
        e(StackOp::Push(PushValue::Int(BigInt::from(BB_P as i128))));
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

/// fieldNeg: (p - a) mod p  (field negation)
fn field_neg(t: &mut BBTracker, a_name: &str, result_name: &str) {
    t.push_int("_zero_neg", 0);
    field_sub(t, "_zero_neg", a_name, result_name);
}

// ===========================================================================
// Ext4 multiplication components
// ===========================================================================

/// Emit ext4 mul component.
/// Stack in: [a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [result]
fn emit_ext4_mul_component(emit: &mut dyn FnMut(StackOp), component: usize) {
    let t = &mut BBTracker::new(&["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"], emit);

    match component {
        0 => {
            // r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b0", "_b0");
            field_mul(t, "_a0", "_b0", "_t0");       // a0*b0
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b3", "_b3");
            field_mul(t, "_a1", "_b3", "_t1");       // a1*b3
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b2", "_b2");
            field_mul(t, "_a2", "_b2", "_t2");       // a2*b2
            field_add(t, "_t1", "_t2", "_t12");      // a1*b3 + a2*b2
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b1", "_b1");
            field_mul(t, "_a3", "_b1", "_t3");       // a3*b1
            field_add(t, "_t12", "_t3", "_cross");   // a1*b3 + a2*b2 + a3*b1
            field_mul_const(t, "_cross", BB_W, "_wcross"); // W * cross
            field_add(t, "_t0", "_wcross", "_r");    // a0*b0 + W*cross
        }
        1 => {
            // r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b1", "_b1");
            field_mul(t, "_a0", "_b1", "_t0");       // a0*b1
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b0", "_b0");
            field_mul(t, "_a1", "_b0", "_t1");       // a1*b0
            field_add(t, "_t0", "_t1", "_direct");   // a0*b1 + a1*b0
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b3", "_b3");
            field_mul(t, "_a2", "_b3", "_t2");       // a2*b3
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b2", "_b2");
            field_mul(t, "_a3", "_b2", "_t3");       // a3*b2
            field_add(t, "_t2", "_t3", "_cross");    // a2*b3 + a3*b2
            field_mul_const(t, "_cross", BB_W, "_wcross"); // W * cross
            field_add(t, "_direct", "_wcross", "_r");
        }
        2 => {
            // r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b2", "_b2");
            field_mul(t, "_a0", "_b2", "_t0");       // a0*b2
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b1", "_b1");
            field_mul(t, "_a1", "_b1", "_t1");       // a1*b1
            field_add(t, "_t0", "_t1", "_sum01");
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b0", "_b0");
            field_mul(t, "_a2", "_b0", "_t2");       // a2*b0
            field_add(t, "_sum01", "_t2", "_direct");
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b3", "_b3");
            field_mul(t, "_a3", "_b3", "_t3");       // a3*b3
            field_mul_const(t, "_t3", BB_W, "_wcross"); // W * a3*b3
            field_add(t, "_direct", "_wcross", "_r");
        }
        3 => {
            // r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b3", "_b3");
            field_mul(t, "_a0", "_b3", "_t0");       // a0*b3
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b2", "_b2");
            field_mul(t, "_a1", "_b2", "_t1");       // a1*b2
            field_add(t, "_t0", "_t1", "_sum01");
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b1", "_b1");
            field_mul(t, "_a2", "_b1", "_t2");       // a2*b1
            field_add(t, "_sum01", "_t2", "_sum012");
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b0", "_b0");
            field_mul(t, "_a3", "_b0", "_t3");       // a3*b0
            field_add(t, "_sum012", "_t3", "_r");
        }
        _ => panic!("Invalid ext4 component: {}", component),
    }

    // Clean up: drop the 8 input values, keep only _r
    for name in &["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"] {
        t.to_top(name);
        t.drop();
    }
    t.to_top("_r");
    t.rename("result");
}

// ===========================================================================
// Ext4 inverse components
// ===========================================================================

/// Emit ext4 inv component.
/// Tower-of-quadratic-extensions algorithm (matches Plonky3):
///
/// norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
/// norm_1 = 2*a0*a2 - a1^2 - W*a3^2
/// det = norm_0^2 - W*norm_1^2
/// scalar = det^(-1)
/// inv_n0 = norm_0 * scalar
/// inv_n1 = -norm_1 * scalar
///
/// r0 = a0*inv_n0 + W*a2*inv_n1
/// r1 = -(a1*inv_n0 + W*a3*inv_n1)
/// r2 = a0*inv_n1 + a2*inv_n0
/// r3 = -(a1*inv_n1 + a3*inv_n0)
///
/// Stack in: [a0, a1, a2, a3]
/// Stack out: [result]
fn emit_ext4_inv_component(emit: &mut dyn FnMut(StackOp), component: usize) {
    let t = &mut BBTracker::new(&["a0", "a1", "a2", "a3"], emit);

    // Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
    t.copy_to_top("a0", "_a0c");
    field_sqr(t, "_a0c", "_a0sq");              // a0^2
    t.copy_to_top("a2", "_a2c");
    field_sqr(t, "_a2c", "_a2sq");              // a2^2
    field_mul_const(t, "_a2sq", BB_W, "_wa2sq");   // W*a2^2
    field_add(t, "_a0sq", "_wa2sq", "_n0a");       // a0^2 + W*a2^2
    t.copy_to_top("a1", "_a1c");
    t.copy_to_top("a3", "_a3c");
    field_mul(t, "_a1c", "_a3c", "_a1a3");      // a1*a3
    // 2*W mod p = 22 (since 22 < p)
    field_mul_const(t, "_a1a3", (BB_W * 2) % BB_P, "_2wa1a3"); // 2*W*a1*a3
    field_sub(t, "_n0a", "_2wa1a3", "_norm0");     // norm_0

    // Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
    t.copy_to_top("a0", "_a0d");
    t.copy_to_top("a2", "_a2d");
    field_mul(t, "_a0d", "_a2d", "_a0a2");      // a0*a2
    field_mul_const(t, "_a0a2", 2, "_2a0a2");      // 2*a0*a2
    t.copy_to_top("a1", "_a1d");
    field_sqr(t, "_a1d", "_a1sq");              // a1^2
    field_sub(t, "_2a0a2", "_a1sq", "_n1a");       // 2*a0*a2 - a1^2
    t.copy_to_top("a3", "_a3d");
    field_sqr(t, "_a3d", "_a3sq");              // a3^2
    field_mul_const(t, "_a3sq", BB_W, "_wa3sq");   // W*a3^2
    field_sub(t, "_n1a", "_wa3sq", "_norm1");      // norm_1

    // Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
    t.copy_to_top("_norm0", "_n0copy");
    field_sqr(t, "_n0copy", "_n0sq");           // norm_0^2
    t.copy_to_top("_norm1", "_n1copy");
    field_sqr(t, "_n1copy", "_n1sq");           // norm_1^2
    field_mul_const(t, "_n1sq", BB_W, "_wn1sq");   // W*norm_1^2
    field_sub(t, "_n0sq", "_wn1sq", "_det");       // norm_0^2 - W*norm_1^2
    field_inv(t, "_det", "_scalar");            // scalar = det^(-1)

    // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
    t.copy_to_top("_scalar", "_sc0");
    field_mul(t, "_norm0", "_sc0", "_inv_n0");     // inv_n0 = norm_0 * scalar

    // -norm_1 = (p - norm_1) mod p
    t.copy_to_top("_norm1", "_neg_n1_pre");
    t.push_int("_pval", BB_P);
    t.to_top("_neg_n1_pre");
    t.raw_block(&["_pval", "_neg_n1_pre"], Some("_neg_n1_sub"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    field_mod(t, "_neg_n1_sub", "_neg_norm1");
    field_mul(t, "_neg_norm1", "_scalar", "_inv_n1");

    // Step 5: Compute result components using quad_mul
    match component {
        0 => {
            // r0 = a0*inv_n0 + W*a2*inv_n1
            t.copy_to_top("a0", "_ea0");
            t.copy_to_top("_inv_n0", "_ein0");
            field_mul(t, "_ea0", "_ein0", "_ep0");       // a0*inv_n0
            t.copy_to_top("a2", "_ea2");
            t.copy_to_top("_inv_n1", "_ein1");
            field_mul(t, "_ea2", "_ein1", "_ep1");       // a2*inv_n1
            field_mul_const(t, "_ep1", BB_W, "_wep1");      // W*a2*inv_n1
            field_add(t, "_ep0", "_wep1", "_r");
        }
        1 => {
            // r1 = -(a1*inv_n0 + W*a3*inv_n1)
            t.copy_to_top("a1", "_oa1");
            t.copy_to_top("_inv_n0", "_oin0");
            field_mul(t, "_oa1", "_oin0", "_op0");       // a1*inv_n0
            t.copy_to_top("a3", "_oa3");
            t.copy_to_top("_inv_n1", "_oin1");
            field_mul(t, "_oa3", "_oin1", "_op1");       // a3*inv_n1
            field_mul_const(t, "_op1", BB_W, "_wop1");      // W*a3*inv_n1
            field_add(t, "_op0", "_wop1", "_odd0");
            // Negate: r = (0 - odd0) mod p
            field_neg(t, "_odd0", "_r");
        }
        2 => {
            // r2 = a0*inv_n1 + a2*inv_n0
            t.copy_to_top("a0", "_ea0");
            t.copy_to_top("_inv_n1", "_ein1");
            field_mul(t, "_ea0", "_ein1", "_ep0");       // a0*inv_n1
            t.copy_to_top("a2", "_ea2");
            t.copy_to_top("_inv_n0", "_ein0");
            field_mul(t, "_ea2", "_ein0", "_ep1");       // a2*inv_n0
            field_add(t, "_ep0", "_ep1", "_r");
        }
        3 => {
            // r3 = -(a1*inv_n1 + a3*inv_n0)
            t.copy_to_top("a1", "_oa1");
            t.copy_to_top("_inv_n1", "_oin1");
            field_mul(t, "_oa1", "_oin1", "_op0");       // a1*inv_n1
            t.copy_to_top("a3", "_oa3");
            t.copy_to_top("_inv_n0", "_oin0");
            field_mul(t, "_oa3", "_oin0", "_op1");       // a3*inv_n0
            field_add(t, "_op0", "_op1", "_odd1");
            // Negate: r = (0 - odd1) mod p
            field_neg(t, "_odd1", "_r");
        }
        _ => panic!("Invalid ext4 component: {}", component),
    }

    // Clean up: drop all intermediate and input values, keep only _r
    let remaining: Vec<String> = t.nm.iter()
        .filter(|n| !n.is_empty() && n.as_str() != "_r")
        .cloned()
        .collect();
    for name in &remaining {
        t.to_top(name);
        t.drop();
    }
    t.to_top("_r");
    t.rename("result");
}

// ===========================================================================
// Public emit functions -- entry points called from stack.rs
// ===========================================================================

/// emitBBFieldAdd: Baby Bear field addition.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a + b) mod p]
pub fn emit_bb_field_add(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut BBTracker::new(&["a", "b"], emit);
    field_add(t, "a", "b", "result");
    // Stack should now be: [result]
}

/// emitBBFieldSub: Baby Bear field subtraction.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a - b) mod p]
pub fn emit_bb_field_sub(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut BBTracker::new(&["a", "b"], emit);
    field_sub(t, "a", "b", "result");
}

/// emitBBFieldMul: Baby Bear field multiplication.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a * b) mod p]
pub fn emit_bb_field_mul(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut BBTracker::new(&["a", "b"], emit);
    field_mul(t, "a", "b", "result");
}

/// emitBBFieldInv: Baby Bear field multiplicative inverse.
/// Stack in: [..., a]
/// Stack out: [..., a^(p-2) mod p]
pub fn emit_bb_field_inv(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut BBTracker::new(&["a"], emit);
    field_inv(t, "a", "result");
}

/// emitBBExt4Mul0: Ext4 multiplication component 0.
/// Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [..., r0]   where r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p
pub fn emit_bb_ext4_mul_0(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 0); }

/// emitBBExt4Mul1: Ext4 multiplication component 1.
/// Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [..., r1]   where r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p
pub fn emit_bb_ext4_mul_1(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 1); }

/// emitBBExt4Mul2: Ext4 multiplication component 2.
/// Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [..., r2]   where r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p
pub fn emit_bb_ext4_mul_2(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 2); }

/// emitBBExt4Mul3: Ext4 multiplication component 3.
/// Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [..., r3]   where r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p
pub fn emit_bb_ext4_mul_3(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 3); }

/// emitBBExt4Inv0: Ext4 inverse component 0.
/// Stack in: [..., a0, a1, a2, a3]
/// Stack out: [..., r0]
pub fn emit_bb_ext4_inv_0(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 0); }

/// emitBBExt4Inv1: Ext4 inverse component 1.
/// Stack in: [..., a0, a1, a2, a3]
/// Stack out: [..., r1]
pub fn emit_bb_ext4_inv_1(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 1); }

/// emitBBExt4Inv2: Ext4 inverse component 2.
/// Stack in: [..., a0, a1, a2, a3]
/// Stack out: [..., r2]
pub fn emit_bb_ext4_inv_2(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 2); }

/// emitBBExt4Inv3: Ext4 inverse component 3.
/// Stack in: [..., a0, a1, a2, a3]
/// Stack out: [..., r3]
pub fn emit_bb_ext4_inv_3(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 3); }
