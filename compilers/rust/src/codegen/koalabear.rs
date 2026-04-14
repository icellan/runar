//! KoalaBear field arithmetic codegen -- KoalaBear prime field operations for Bitcoin Script.
//!
//! Port of compilers/go/codegen/koalabear.go.
//! Follows the babybear.rs pattern: self-contained module imported by stack.rs.
//! Uses a KBTracker for named stack state tracking.
//!
//! KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433 (0x7f000001)
//! Used by SP1 v6 STARK proofs (StackedBasefold verification).
//!
//! All values fit in a single BSV script number (31-bit prime).
//! No multi-limb arithmetic needed.

use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// KoalaBear field prime p = 2^31 - 2^24 + 1
pub(crate) const KB_P: i64 = 2130706433;
/// p - 2, used for Fermat's little theorem modular inverse
pub(crate) const KB_P_MINUS_2: i64 = 2130706431;
/// Quartic extension irreducible polynomial coefficient W = 3
pub(crate) const KB_W: i64 = 3;

// ===========================================================================
// KBTracker -- named stack state tracker (mirrors BBTracker)
// ===========================================================================

pub(crate) struct KBTracker<'a> {
    pub(crate) nm: Vec<String>,
    pub(crate) e: &'a mut dyn FnMut(StackOp),
    pub(crate) prime_cache_active: bool,
}

#[allow(dead_code)]
impl<'a> KBTracker<'a> {
    pub(crate) fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        KBTracker {
            nm: init.iter().map(|s| s.to_string()).collect(),
            e: emit,
            prime_cache_active: false,
        }
    }

    pub(crate) fn new_from_strings(init: &[String], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        KBTracker {
            nm: init.to_vec(),
            e: emit,
            prime_cache_active: false,
        }
    }

    pub(crate) fn depth(&self) -> usize {
        self.nm.len()
    }

    pub(crate) fn find_depth(&self, name: &str) -> usize {
        for i in (0..self.nm.len()).rev() {
            if self.nm[i] == name {
                return self.nm.len() - 1 - i;
            }
        }
        panic!("KBTracker: '{}' not on stack {:?}", name, self.nm);
    }

    pub(crate) fn push_int(&mut self, n: &str, v: i64) {
        (self.e)(StackOp::Push(PushValue::Int(v as i128)));
        self.nm.push(n.to_string());
    }

    pub(crate) fn dup(&mut self, n: &str) {
        (self.e)(StackOp::Dup);
        self.nm.push(n.to_string());
    }

    pub(crate) fn drop(&mut self) {
        (self.e)(StackOp::Drop);
        if !self.nm.is_empty() {
            self.nm.pop();
        }
    }

    pub(crate) fn nip(&mut self) {
        (self.e)(StackOp::Nip);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.remove(len - 2);
        }
    }

    pub(crate) fn over(&mut self, n: &str) {
        (self.e)(StackOp::Over);
        self.nm.push(n.to_string());
    }

    pub(crate) fn swap(&mut self) {
        (self.e)(StackOp::Swap);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.swap(len - 1, len - 2);
        }
    }

    pub(crate) fn rot(&mut self) {
        (self.e)(StackOp::Rot);
        let len = self.nm.len();
        if len >= 3 {
            let r = self.nm.remove(len - 3);
            self.nm.push(r);
        }
    }

    pub(crate) fn pick(&mut self, depth: usize, n: &str) {
        if depth == 0 {
            self.dup(n);
            return;
        }
        if depth == 1 {
            self.over(n);
            return;
        }
        (self.e)(StackOp::Push(PushValue::Int(depth as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Pick { depth });
        self.nm.pop();
        self.nm.push(n.to_string());
    }

    pub(crate) fn roll(&mut self, d: usize) {
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
        (self.e)(StackOp::Roll { depth: d });
        self.nm.pop();
        let idx = self.nm.len() - 1 - d;
        let item = self.nm.remove(idx);
        self.nm.push(item);
    }

    /// Bring a named value to stack top (non-consuming copy via PICK).
    pub(crate) fn copy_to_top(&mut self, name: &str, new_name: &str) {
        let d = self.find_depth(name);
        self.pick(d, new_name);
    }

    /// Bring a named value to stack top (consuming via ROLL).
    pub(crate) fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        if d == 0 {
            return;
        }
        self.roll(d);
    }

    /// Rename the top-of-stack entry.
    pub(crate) fn rename(&mut self, new_name: &str) {
        if let Some(last) = self.nm.last_mut() {
            *last = new_name.to_string();
        }
    }

    /// Emit raw opcodes; tracker only records net stack effect.
    pub(crate) fn raw_block(
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

    /// Push the KoalaBear prime to the alt-stack for caching.
    /// All subsequent field operations will use the cached prime instead of pushing fresh.
    pub(crate) fn push_prime_cache(&mut self) {
        (self.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (self.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        self.prime_cache_active = true;
    }

    /// Remove the cached prime from the alt-stack.
    pub(crate) fn pop_prime_cache(&mut self) {
        (self.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (self.e)(StackOp::Drop);
        self.prime_cache_active = false;
    }

    /// Emit the field prime onto the stack -- either from cache or fresh push.
    pub(crate) fn emit_prime(&mut self) {
        let active = self.prime_cache_active;
        if active {
            (self.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
            (self.e)(StackOp::Dup);
            (self.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        } else {
            (self.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        }
    }
}

// ===========================================================================
// Field arithmetic internals
// ===========================================================================

/// kbFieldMod: ensure value is in [0, p).
/// Pattern: (a % p + p) % p -- handles negative values from sub.
pub(crate) fn kb_field_mod(t: &mut KBTracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    // consume a_name, produce result_name
    let len = t.nm.len();
    if len > 0 {
        t.nm.pop();
    }
    let active = t.prime_cache_active;
    if active {
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_ADD".into()));
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    } else {
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_ADD".into()));
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    }
    t.nm.push(result_name.to_string());
}

/// kbFieldAddUnreduced: a + b WITHOUT modular reduction.
/// Result is in [0, 2p-2]. Safe when immediately consumed by mul or further additions.
pub(crate) fn kb_field_add_unreduced(t: &mut KBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some(result_name), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
}

/// kbFieldAdd: (a + b) mod p
pub(crate) fn kb_field_add(t: &mut KBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_kb_add"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    // Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    t.to_top("_kb_add");
    let active = t.prime_cache_active;
    let len = t.nm.len();
    if len > 0 {
        t.nm.pop();
    }
    if active {
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    } else {
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    }
    t.nm.push(result_name.to_string());
}

/// kbFieldSub: (a - b) mod p (non-negative)
pub(crate) fn kb_field_sub(t: &mut KBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_kb_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    // Difference can be negative, need full mod-reduce
    kb_field_mod(t, "_kb_diff", result_name);
}

/// kbFieldMul: (a * b) mod p
pub(crate) fn kb_field_mul(t: &mut KBTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_kb_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    // Product of two non-negative values is non-negative, simple OP_MOD
    t.to_top("_kb_prod");
    let active = t.prime_cache_active;
    let len = t.nm.len();
    if len > 0 {
        t.nm.pop();
    }
    if active {
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    } else {
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    }
    t.nm.push(result_name.to_string());
}

/// kbFieldSqr: (a * a) mod p
pub(crate) fn kb_field_sqr(t: &mut KBTracker, a_name: &str, result_name: &str) {
    t.copy_to_top(a_name, "_kb_sqr_copy");
    kb_field_mul(t, a_name, "_kb_sqr_copy", result_name);
}

/// kbFieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
/// p-2 = 2130706431 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
/// 31 bits, popcount 30.
/// ~30 squarings + ~29 multiplies = ~59 compound operations.
pub(crate) fn kb_field_inv(t: &mut KBTracker, a_name: &str, result_name: &str) {
    // Start: result = a (for MSB bit 30 = 1)
    t.copy_to_top(a_name, "_inv_r");

    // Process bits 29 down to 0 (30 bits)
    let p_minus_2 = KB_P_MINUS_2 as u64;
    for i in (0..=29i32).rev() {
        // Always square
        kb_field_sqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");

        // Multiply if bit is set
        if (p_minus_2 >> (i as u32)) & 1 == 1 {
            t.copy_to_top(a_name, "_inv_a");
            kb_field_mul(t, "_inv_r", "_inv_a", "_inv_m");
            t.rename("_inv_r");
        }
    }

    // Clean up original input and rename result
    t.to_top(a_name);
    t.drop();
    t.to_top("_inv_r");
    t.rename(result_name);
}

/// kbFieldMulConst: (a * c) mod p where c is a compile-time constant.
/// Uses OP_2MUL when c==2 and OP_LSHIFTNUM when c is a power of 2 > 2.
pub(crate) fn kb_field_mul_const(t: &mut KBTracker, a_name: &str, c: i64, result_name: &str) {
    t.to_top(a_name);
    if c == 2 {
        let len = t.nm.len();
        if len > 0 { t.nm.pop(); }
        (t.e)(StackOp::Opcode("OP_2MUL".into()));
        t.nm.push("_kb_mc".to_string());
    } else if c > 2 && (c & (c - 1)) == 0 {
        // power of 2
        let shift = c.trailing_zeros();
        let len = t.nm.len();
        if len > 0 { t.nm.pop(); }
        (t.e)(StackOp::Push(PushValue::Int(shift as i128)));
        (t.e)(StackOp::Opcode("OP_LSHIFTNUM".into()));
        t.nm.push("_kb_mc".to_string());
    } else {
        t.raw_block(&[a_name], Some("_kb_mc"), |e| {
            e(StackOp::Push(PushValue::Int(c as i128)));
            e(StackOp::Opcode("OP_MUL".into()));
        });
    }
    // mod reduction -- uses cached prime when available
    t.to_top("_kb_mc");
    let active = t.prime_cache_active;
    let len = t.nm.len();
    if len > 0 { t.nm.pop(); }
    if active {
        (t.e)(StackOp::Opcode("OP_FROMALTSTACK".into()));
        (t.e)(StackOp::Dup);
        (t.e)(StackOp::Opcode("OP_TOALTSTACK".into()));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    } else {
        (t.e)(StackOp::Push(PushValue::Int(KB_P as i128)));
        (t.e)(StackOp::Opcode("OP_MOD".into()));
    }
    t.nm.push(result_name.to_string());
}

// ===========================================================================
// Ext4 multiplication components
// ===========================================================================

/// Emit ext4 mul component.
/// Stack in: [a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [result]
fn emit_ext4_mul_component(emit: &mut dyn FnMut(StackOp), component: usize) {
    let t = &mut KBTracker::new(&["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"], emit);

    match component {
        0 => {
            // r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b0", "_b0");
            kb_field_mul(t, "_a0", "_b0", "_t0");       // a0*b0
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b3", "_b3");
            kb_field_mul(t, "_a1", "_b3", "_t1");       // a1*b3
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b2", "_b2");
            kb_field_mul(t, "_a2", "_b2", "_t2");       // a2*b2
            kb_field_add(t, "_t1", "_t2", "_t12");      // a1*b3 + a2*b2
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b1", "_b1");
            kb_field_mul(t, "_a3", "_b1", "_t3");       // a3*b1
            kb_field_add(t, "_t12", "_t3", "_cross");   // a1*b3 + a2*b2 + a3*b1
            kb_field_mul_const(t, "_cross", KB_W, "_wcross"); // W * cross
            kb_field_add(t, "_t0", "_wcross", "_r");    // a0*b0 + W*cross
        }
        1 => {
            // r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b1", "_b1");
            kb_field_mul(t, "_a0", "_b1", "_t0");       // a0*b1
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b0", "_b0");
            kb_field_mul(t, "_a1", "_b0", "_t1");       // a1*b0
            kb_field_add(t, "_t0", "_t1", "_direct");   // a0*b1 + a1*b0
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b3", "_b3");
            kb_field_mul(t, "_a2", "_b3", "_t2");       // a2*b3
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b2", "_b2");
            kb_field_mul(t, "_a3", "_b2", "_t3");       // a3*b2
            kb_field_add(t, "_t2", "_t3", "_cross");    // a2*b3 + a3*b2
            kb_field_mul_const(t, "_cross", KB_W, "_wcross"); // W * cross
            kb_field_add(t, "_direct", "_wcross", "_r");
        }
        2 => {
            // r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b2", "_b2");
            kb_field_mul(t, "_a0", "_b2", "_t0");       // a0*b2
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b1", "_b1");
            kb_field_mul(t, "_a1", "_b1", "_t1");       // a1*b1
            kb_field_add(t, "_t0", "_t1", "_sum01");
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b0", "_b0");
            kb_field_mul(t, "_a2", "_b0", "_t2");       // a2*b0
            kb_field_add(t, "_sum01", "_t2", "_direct");
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b3", "_b3");
            kb_field_mul(t, "_a3", "_b3", "_t3");       // a3*b3
            kb_field_mul_const(t, "_t3", KB_W, "_wcross"); // W * a3*b3
            kb_field_add(t, "_direct", "_wcross", "_r");
        }
        3 => {
            // r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
            t.copy_to_top("a0", "_a0"); t.copy_to_top("b3", "_b3");
            kb_field_mul(t, "_a0", "_b3", "_t0");       // a0*b3
            t.copy_to_top("a1", "_a1"); t.copy_to_top("b2", "_b2");
            kb_field_mul(t, "_a1", "_b2", "_t1");       // a1*b2
            kb_field_add(t, "_t0", "_t1", "_sum01");
            t.copy_to_top("a2", "_a2"); t.copy_to_top("b1", "_b1");
            kb_field_mul(t, "_a2", "_b1", "_t2");       // a2*b1
            kb_field_add(t, "_sum01", "_t2", "_sum012");
            t.copy_to_top("a3", "_a3"); t.copy_to_top("b0", "_b0");
            kb_field_mul(t, "_a3", "_b0", "_t3");       // a3*b0
            kb_field_add(t, "_sum012", "_t3", "_r");
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
    let t = &mut KBTracker::new(&["a0", "a1", "a2", "a3"], emit);

    // Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
    t.copy_to_top("a0", "_a0c");
    kb_field_sqr(t, "_a0c", "_a0sq");              // a0^2
    t.copy_to_top("a2", "_a2c");
    kb_field_sqr(t, "_a2c", "_a2sq");              // a2^2
    kb_field_mul_const(t, "_a2sq", KB_W, "_wa2sq");   // W*a2^2
    kb_field_add(t, "_a0sq", "_wa2sq", "_n0a");       // a0^2 + W*a2^2
    t.copy_to_top("a1", "_a1c");
    t.copy_to_top("a3", "_a3c");
    kb_field_mul(t, "_a1c", "_a3c", "_a1a3");      // a1*a3
    kb_field_mul_const(t, "_a1a3", 2 * KB_W, "_2wa1a3"); // 2*W*a1*a3
    kb_field_sub(t, "_n0a", "_2wa1a3", "_norm0");     // norm_0

    // Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
    t.copy_to_top("a0", "_a0d");
    t.copy_to_top("a2", "_a2d");
    kb_field_mul(t, "_a0d", "_a2d", "_a0a2");      // a0*a2
    kb_field_mul_const(t, "_a0a2", 2, "_2a0a2");      // 2*a0*a2
    t.copy_to_top("a1", "_a1d");
    kb_field_sqr(t, "_a1d", "_a1sq");              // a1^2
    kb_field_sub(t, "_2a0a2", "_a1sq", "_n1a");       // 2*a0*a2 - a1^2
    t.copy_to_top("a3", "_a3d");
    kb_field_sqr(t, "_a3d", "_a3sq");              // a3^2
    kb_field_mul_const(t, "_a3sq", KB_W, "_wa3sq");   // W*a3^2
    kb_field_sub(t, "_n1a", "_wa3sq", "_norm1");      // norm_1

    // Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
    t.copy_to_top("_norm0", "_n0copy");
    kb_field_sqr(t, "_n0copy", "_n0sq");           // norm_0^2
    t.copy_to_top("_norm1", "_n1copy");
    kb_field_sqr(t, "_n1copy", "_n1sq");           // norm_1^2
    kb_field_mul_const(t, "_n1sq", KB_W, "_wn1sq");   // W*norm_1^2
    kb_field_sub(t, "_n0sq", "_wn1sq", "_det");       // norm_0^2 - W*norm_1^2
    kb_field_inv(t, "_det", "_scalar");            // scalar = det^(-1)

    // Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
    t.copy_to_top("_scalar", "_sc0");
    kb_field_mul(t, "_norm0", "_sc0", "_inv_n0");     // inv_n0 = norm_0 * scalar

    // -norm_1 = (p - norm_1) mod p
    t.copy_to_top("_norm1", "_neg_n1_pre");
    t.push_int("_pval", KB_P);
    t.to_top("_neg_n1_pre");
    t.raw_block(&["_pval", "_neg_n1_pre"], Some("_neg_n1_sub"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
    kb_field_mod(t, "_neg_n1_sub", "_neg_norm1");
    kb_field_mul(t, "_neg_norm1", "_scalar", "_inv_n1");

    // Step 5: Compute result components using quad_mul
    match component {
        0 => {
            // r0 = a0*inv_n0 + W*a2*inv_n1
            t.copy_to_top("a0", "_ea0");
            t.copy_to_top("_inv_n0", "_ein0");
            kb_field_mul(t, "_ea0", "_ein0", "_ep0");       // a0*inv_n0
            t.copy_to_top("a2", "_ea2");
            t.copy_to_top("_inv_n1", "_ein1");
            kb_field_mul(t, "_ea2", "_ein1", "_ep1");       // a2*inv_n1
            kb_field_mul_const(t, "_ep1", KB_W, "_wep1");      // W*a2*inv_n1
            kb_field_add(t, "_ep0", "_wep1", "_r");
        }
        1 => {
            // r1 = -(a1*inv_n0 + W*a3*inv_n1)
            t.copy_to_top("a1", "_oa1");
            t.copy_to_top("_inv_n0", "_oin0");
            kb_field_mul(t, "_oa1", "_oin0", "_op0");       // a1*inv_n0
            t.copy_to_top("a3", "_oa3");
            t.copy_to_top("_inv_n1", "_oin1");
            kb_field_mul(t, "_oa3", "_oin1", "_op1");       // a3*inv_n1
            kb_field_mul_const(t, "_op1", KB_W, "_wop1");      // W*a3*inv_n1
            kb_field_add(t, "_op0", "_wop1", "_odd0");
            // Negate: r = (0 - odd0) mod p
            t.push_int("_zero1", 0);
            kb_field_sub(t, "_zero1", "_odd0", "_r");
        }
        2 => {
            // r2 = a0*inv_n1 + a2*inv_n0
            t.copy_to_top("a0", "_ea0");
            t.copy_to_top("_inv_n1", "_ein1");
            kb_field_mul(t, "_ea0", "_ein1", "_ep0");       // a0*inv_n1
            t.copy_to_top("a2", "_ea2");
            t.copy_to_top("_inv_n0", "_ein0");
            kb_field_mul(t, "_ea2", "_ein0", "_ep1");       // a2*inv_n0
            kb_field_add(t, "_ep0", "_ep1", "_r");
        }
        3 => {
            // r3 = -(a1*inv_n1 + a3*inv_n0)
            t.copy_to_top("a1", "_oa1");
            t.copy_to_top("_inv_n1", "_oin1");
            kb_field_mul(t, "_oa1", "_oin1", "_op0");       // a1*inv_n1
            t.copy_to_top("a3", "_oa3");
            t.copy_to_top("_inv_n0", "_oin0");
            kb_field_mul(t, "_oa3", "_oin0", "_op1");       // a3*inv_n0
            kb_field_add(t, "_op0", "_op1", "_odd1");
            // Negate: r = (0 - odd1) mod p
            t.push_int("_zero3", 0);
            kb_field_sub(t, "_zero3", "_odd1", "_r");
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

/// emit_kb_field_add: KoalaBear field addition.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a + b) mod p]
pub fn emit_kb_field_add(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut KBTracker::new(&["a", "b"], emit);
    kb_field_add(t, "a", "b", "result");
}

/// emit_kb_field_sub: KoalaBear field subtraction.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a - b) mod p]
pub fn emit_kb_field_sub(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut KBTracker::new(&["a", "b"], emit);
    kb_field_sub(t, "a", "b", "result");
}

/// emit_kb_field_mul: KoalaBear field multiplication.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a * b) mod p]
pub fn emit_kb_field_mul(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut KBTracker::new(&["a", "b"], emit);
    kb_field_mul(t, "a", "b", "result");
}

/// emit_kb_field_inv: KoalaBear field multiplicative inverse.
/// Stack in: [..., a]
/// Stack out: [..., a^(p-2) mod p]
pub fn emit_kb_field_inv(emit: &mut dyn FnMut(StackOp)) {
    let t = &mut KBTracker::new(&["a"], emit);
    kb_field_inv(t, "a", "result");
}

/// emit_kb_ext4_mul_0: Ext4 multiplication component 0.
/// Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3]
/// Stack out: [..., r0]   where r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p
pub fn emit_kb_ext4_mul_0(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 0); }

/// emit_kb_ext4_mul_1: Ext4 multiplication component 1.
pub fn emit_kb_ext4_mul_1(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 1); }

/// emit_kb_ext4_mul_2: Ext4 multiplication component 2.
pub fn emit_kb_ext4_mul_2(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 2); }

/// emit_kb_ext4_mul_3: Ext4 multiplication component 3.
pub fn emit_kb_ext4_mul_3(emit: &mut dyn FnMut(StackOp)) { emit_ext4_mul_component(emit, 3); }

/// emit_kb_ext4_inv_0: Ext4 inverse component 0.
pub fn emit_kb_ext4_inv_0(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 0); }

/// emit_kb_ext4_inv_1: Ext4 inverse component 1.
pub fn emit_kb_ext4_inv_1(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 1); }

/// emit_kb_ext4_inv_2: Ext4 inverse component 2.
pub fn emit_kb_ext4_inv_2(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 2); }

/// emit_kb_ext4_inv_3: Ext4 inverse component 3.
pub fn emit_kb_ext4_inv_3(emit: &mut dyn FnMut(StackOp)) { emit_ext4_inv_component(emit, 3); }
