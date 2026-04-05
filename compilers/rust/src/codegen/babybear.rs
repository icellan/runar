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

use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// Baby Bear field prime p = 2^31 - 2^27 + 1
const BB_P: i64 = 2013265921;
/// p - 2, used for Fermat's little theorem modular inverse
const BB_P_MINUS_2: i64 = BB_P - 2;

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
        (self.e)(StackOp::Push(PushValue::Int(v as i128)));
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
        (self.e)(StackOp::Push(PushValue::Int(depth as i128)));
        self.nm.push(String::new());
        (self.e)(StackOp::Pick { depth });
        self.nm.pop();
        self.nm.push(n.to_string());
    }

    fn roll(&mut self, d: usize) {
        if d == 0 { return; }
        if d == 1 { self.swap(); return; }
        if d == 2 { self.rot(); return; }
        (self.e)(StackOp::Push(PushValue::Int(d as i128)));
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
        e(StackOp::Push(PushValue::Int(BB_P as i128)));
        e(StackOp::Opcode("OP_MOD".into()));
        e(StackOp::Push(PushValue::Int(BB_P as i128)));
        e(StackOp::Opcode("OP_ADD".into()));
        e(StackOp::Push(PushValue::Int(BB_P as i128)));
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
        e(StackOp::Push(PushValue::Int(BB_P as i128)));
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
        e(StackOp::Push(PushValue::Int(BB_P as i128)));
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
