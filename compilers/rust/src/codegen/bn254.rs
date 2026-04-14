//! BN254 codegen -- BN254 elliptic curve field arithmetic and G1 point operations
//! for Bitcoin Script.
//!
//! Port of compilers/go/codegen/bn254.go (bn254.go only -- bn254_flat.go is a
//! Go-only optimization and is NOT ported).
//!
//! Follows the ec.rs / koalabear.rs pattern: self-contained module imported by
//! stack.rs. Uses a BN254Tracker (mirrors ECTracker) for named stack state
//! tracking with an alt-stack prime cache.
//!
//! BN254 parameters:
//!   Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
//!   Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!   Curve:       y^2 = x^3 + 3
//!   Generator:   G1 = (1, 2)
//!
//! Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
//! Internal arithmetic uses Jacobian coordinates for scalar multiplication.

use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// BN254 field prime p in big-endian bytes.
/// p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
#[allow(dead_code)]
const BN254_FIELD_P_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 field prime p as a Bitcoin script number (little-endian sign-magnitude).
/// 32 bytes; MSB (0x30) has bit 7 clear so no sign byte is needed.
const BN254_FIELD_P_SCRIPT_NUM: [u8; 32] = [
    0x47, 0xfd, 0x7c, 0xd8, 0x16, 0x8c, 0x20, 0x3c,
    0x8d, 0xca, 0x71, 0x68, 0x91, 0x6a, 0x81, 0x97,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// BN254 curve order r as a Bitcoin script number (little-endian sign-magnitude).
/// r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
/// 32 bytes; MSB (0x30) has bit 7 clear so no sign byte is needed.
const BN254_CURVE_R_SCRIPT_NUM: [u8; 32] = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43,
    0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8,
    0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// p - 2 in big-endian bytes (for Fermat's little theorem modular inverse).
/// Only differs from p in the low byte (0x47 -> 0x45).
const BN254_FIELD_P_MINUS_2_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
    0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x45,
];

/// Test bit `i` of p - 2, where bit 0 is the LSB.
fn bn254_p_minus_2_bit(i: usize) -> bool {
    let byte_from_lsb = i / 8;
    let bit = i % 8;
    // BE array: byte at index (31 - byte_from_lsb) is the byte containing bit `i`.
    let byte_idx = 31 - byte_from_lsb;
    (BN254_FIELD_P_MINUS_2_BE[byte_idx] >> bit) & 1 == 1
}

/// Collect ops into a Vec via closure.
fn collect_ops(f: impl FnOnce(&mut dyn FnMut(StackOp))) -> Vec<StackOp> {
    let mut ops = Vec::new();
    f(&mut |op| ops.push(op));
    ops
}

// ===========================================================================
// BN254Tracker -- named stack state tracker (mirrors ECTracker)
// ===========================================================================

pub(crate) struct BN254Tracker<'a> {
    pub(crate) nm: Vec<String>,
    pub(crate) e: &'a mut dyn FnMut(StackOp),
    pub(crate) prime_cache_active: bool,
}

#[allow(dead_code)]
impl<'a> BN254Tracker<'a> {
    pub(crate) fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        BN254Tracker {
            nm: init.iter().map(|s| s.to_string()).collect(),
            e: emit,
            prime_cache_active: false,
        }
    }

    pub(crate) fn new_from_strings(init: &[String], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        BN254Tracker {
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
        panic!("BN254Tracker: '{}' not on stack {:?}", name, self.nm);
    }

    pub(crate) fn push_bytes(&mut self, n: &str, v: Vec<u8>) {
        (self.e)(StackOp::Push(PushValue::Bytes(v)));
        self.nm.push(n.to_string());
    }

    pub(crate) fn push_int(&mut self, n: &str, v: i128) {
        (self.e)(StackOp::Push(PushValue::Int(v)));
        self.nm.push(n.to_string());
    }

    /// Push the BN254 field prime p as a script number.
    pub(crate) fn push_field_p(&mut self, n: &str) {
        self.push_bytes(n, BN254_FIELD_P_SCRIPT_NUM.to_vec());
    }

    /// Push the BN254 curve order r as a script number.
    pub(crate) fn push_curve_r(&mut self, n: &str) {
        self.push_bytes(n, BN254_CURVE_R_SCRIPT_NUM.to_vec());
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

    pub(crate) fn op(&mut self, code: &str) {
        (self.e)(StackOp::Opcode(code.into()));
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

    pub(crate) fn pick(&mut self, d: usize, n: &str) {
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
        (self.e)(StackOp::Pick { depth: d });
        self.nm.pop();
        self.nm.push(n.to_string());
    }

    pub(crate) fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        if d == 0 {
            return;
        }
        self.roll(d);
    }

    pub(crate) fn copy_to_top(&mut self, name: &str, n: &str) {
        let d = self.find_depth(name);
        self.pick(d, n);
    }

    pub(crate) fn to_alt(&mut self) {
        self.op("OP_TOALTSTACK");
        if !self.nm.is_empty() {
            self.nm.pop();
        }
    }

    pub(crate) fn from_alt(&mut self, n: &str) {
        self.op("OP_FROMALTSTACK");
        self.nm.push(n.to_string());
    }

    pub(crate) fn rename(&mut self, n: &str) {
        if let Some(last) = self.nm.last_mut() {
            *last = n.to_string();
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

    /// Push the BN254 field prime onto the alt-stack for caching.
    /// Subsequent field-mod calls use OP_FROMALTSTACK/DUP/OP_TOALTSTACK
    /// instead of pushing the 34-byte prime literal every time.
    pub(crate) fn push_prime_cache(&mut self) {
        self.push_field_p("_pcache_p");
        self.op("OP_TOALTSTACK");
        if !self.nm.is_empty() {
            self.nm.pop();
        }
        self.prime_cache_active = true;
    }

    /// Remove the cached field prime from the alt-stack.
    pub(crate) fn pop_prime_cache(&mut self) {
        self.op("OP_FROMALTSTACK");
        self.nm.push("_pcache_cleanup".to_string());
        self.drop();
        self.prime_cache_active = false;
    }
}

// ===========================================================================
// Field arithmetic helpers
// ===========================================================================

/// bn254_field_mod: reduce TOS mod p, ensure non-negative.
/// Pattern: (a % p + p) % p
pub(crate) fn bn254_field_mod(t: &mut BN254Tracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    let active = t.prime_cache_active;
    if active {
        t.raw_block(&[a_name], Some(result_name), |e| {
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
            e(StackOp::Opcode("OP_DUP".into()));
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            // [a, p] -> TUCK -> [p, a, p]
            e(StackOp::Opcode("OP_TUCK".into()));
            // [p, a, p] -> MOD -> [p, a%p]
            e(StackOp::Opcode("OP_MOD".into()));
            // [p, a%p] -> OVER -> [p, a%p, p]
            e(StackOp::Over);
            // [p, a%p, p] -> ADD -> [p, a%p+p]
            e(StackOp::Opcode("OP_ADD".into()));
            // [p, a%p+p] -> SWAP -> [a%p+p, p]
            e(StackOp::Swap);
            // [a%p+p, p] -> MOD -> [(a%p+p)%p]
            e(StackOp::Opcode("OP_MOD".into()));
        });
    } else {
        t.push_field_p("_fmod_p");
        t.raw_block(&[a_name, "_fmod_p"], Some(result_name), |e| {
            e(StackOp::Opcode("OP_TUCK".into()));
            e(StackOp::Opcode("OP_MOD".into()));
            e(StackOp::Over);
            e(StackOp::Opcode("OP_ADD".into()));
            e(StackOp::Swap);
            e(StackOp::Opcode("OP_MOD".into()));
        });
    }
}

/// bn254_field_mod_positive: reduce a non-negative value mod p using a single OP_MOD.
/// SAFETY: only use when the input is guaranteed non-negative.
pub(crate) fn bn254_field_mod_positive(
    t: &mut BN254Tracker,
    a_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    let active = t.prime_cache_active;
    if active {
        t.raw_block(&[a_name], Some(result_name), |e| {
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
            e(StackOp::Opcode("OP_DUP".into()));
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            // [a, p] -> a % p
            e(StackOp::Opcode("OP_MOD".into()));
        });
    } else {
        t.push_field_p("_fmodp_p");
        t.raw_block(&[a_name, "_fmodp_p"], Some(result_name), |e| {
            e(StackOp::Opcode("OP_MOD".into()));
        });
    }
}

/// bn254_field_add: (a + b) mod p.
pub(crate) fn bn254_field_add(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fadd_sum"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    bn254_field_mod_positive(t, "_fadd_sum", result_name);
}

/// bn254_field_add_unreduced: a + b WITHOUT modular reduction.
pub(crate) fn bn254_field_add_unreduced(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some(result_name), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
}

/// bn254_field_sub_unreduced: a - b WITHOUT modular reduction.
pub(crate) fn bn254_field_sub_unreduced(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some(result_name), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });
}

/// bn254_field_mul_unreduced: a * b WITHOUT modular reduction.
pub(crate) fn bn254_field_mul_unreduced(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some(result_name), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
}

/// bn254_field_sub: (a - b) mod p (non-negative).
/// Pattern: (a - b + p) mod p.
pub(crate) fn bn254_field_sub(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    let active = t.prime_cache_active;
    if active {
        t.raw_block(&[a_name, b_name], Some(result_name), |e| {
            e(StackOp::Opcode("OP_SUB".into())); // [diff]
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
            e(StackOp::Opcode("OP_DUP".into()));
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            // [diff, p] -> TUCK -> [p, diff, p]
            e(StackOp::Opcode("OP_TUCK".into()));
            // [p, diff, p] -> ADD -> [p, diff+p]
            e(StackOp::Opcode("OP_ADD".into()));
            // [p, diff+p] -> SWAP -> [diff+p, p]
            e(StackOp::Swap);
            // [diff+p, p] -> MOD -> [(diff+p)%p]
            e(StackOp::Opcode("OP_MOD".into()));
        });
    } else {
        t.raw_block(&[a_name, b_name], Some("_fsub_diff"), |e| {
            e(StackOp::Opcode("OP_SUB".into()));
        });
        bn254_field_mod(t, "_fsub_diff", result_name);
    }
}

/// bn254_field_mul: (a * b) mod p.
pub(crate) fn bn254_field_mul(
    t: &mut BN254Tracker,
    a_name: &str,
    b_name: &str,
    result_name: &str,
) {
    t.to_top(a_name);
    t.to_top(b_name);
    t.raw_block(&[a_name, b_name], Some("_fmul_prod"), |e| {
        e(StackOp::Opcode("OP_MUL".into()));
    });
    bn254_field_mod_positive(t, "_fmul_prod", result_name);
}

/// bn254_field_sqr: (a * a) mod p.
pub(crate) fn bn254_field_sqr(t: &mut BN254Tracker, a_name: &str, result_name: &str) {
    t.copy_to_top(a_name, "_fsqr_copy");
    bn254_field_mul(t, a_name, "_fsqr_copy", result_name);
}

/// bn254_field_neg: (p - a) mod p.
pub(crate) fn bn254_field_neg(t: &mut BN254Tracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    let active = t.prime_cache_active;
    if active {
        t.raw_block(&[a_name], Some(result_name), |e| {
            // [a]
            e(StackOp::Opcode("OP_FROMALTSTACK".into()));
            e(StackOp::Opcode("OP_DUP".into()));
            e(StackOp::Opcode("OP_TOALTSTACK".into()));
            // [a, p] -> DUP -> [a, p, p]
            e(StackOp::Opcode("OP_DUP".into()));
            // [a, p, p] -> ROT -> [p, p, a]
            e(StackOp::Rot);
            // [p, p, a] -> SUB -> [p, p-a]
            e(StackOp::Opcode("OP_SUB".into()));
            // [p, p-a] -> SWAP -> [p-a, p]
            e(StackOp::Swap);
            // [p-a, p] -> MOD -> [(p-a)%p]
            e(StackOp::Opcode("OP_MOD".into()));
        });
    } else {
        t.push_field_p("_fneg_p");
        t.raw_block(&[a_name, "_fneg_p"], Some(result_name), |e| {
            e(StackOp::Opcode("OP_DUP".into()));
            e(StackOp::Rot);
            e(StackOp::Opcode("OP_SUB".into()));
            e(StackOp::Swap);
            e(StackOp::Opcode("OP_MOD".into()));
        });
    }
}

/// bn254_field_mul_const: (a * c) mod p where c is a small positive constant.
pub(crate) fn bn254_field_mul_const(
    t: &mut BN254Tracker,
    a_name: &str,
    c: i64,
    result_name: &str,
) {
    t.to_top(a_name);
    t.raw_block(&[a_name], Some("_bn_mc"), |e| {
        if c == 2 {
            e(StackOp::Opcode("OP_2MUL".into()));
        } else {
            e(StackOp::Push(PushValue::Int(c as i128)));
            e(StackOp::Opcode("OP_MUL".into()));
        }
    });
    bn254_field_mod_positive(t, "_bn_mc", result_name);
}

/// bn254_field_inv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
///
/// BN254 p is a 254-bit prime, so p-2 is also 254 bits with MSB at bit 253.
/// Initializing result = a is equivalent to processing bit 253 with an empty
/// accumulator; then loop over bits 252 down to 0. 253 squarings + 109 multiplies.
pub(crate) fn bn254_field_inv(t: &mut BN254Tracker, a_name: &str, result_name: &str) {
    // result = a implicitly handles bit 253 (the MSB of p-2, always set)
    t.copy_to_top(a_name, "_inv_r");

    // Process bits 252 down to 0 (253 iterations, one squaring each)
    for i in (0..=252i32).rev() {
        // Always square
        bn254_field_sqr(t, "_inv_r", "_inv_r2");
        t.rename("_inv_r");

        // Multiply if bit is set
        if bn254_p_minus_2_bit(i as usize) {
            t.copy_to_top(a_name, "_inv_a");
            bn254_field_mul(t, "_inv_r", "_inv_a", "_inv_m");
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

/// Emit inline byte reversal for a 32-byte value on TOS.
fn emit_reverse_32(e: &mut dyn FnMut(StackOp)) {
    // Push empty accumulator, swap with data
    e(StackOp::Opcode("OP_0".into()));
    e(StackOp::Swap);
    // 32 iterations: peel first byte, prepend to accumulator
    for _i in 0..32 {
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

/// bn254_decompose_point: decompose a 64-byte Point into (x_num, y_num) on stack.
/// Consumes pointName, produces xName and yName.
pub(crate) fn bn254_decompose_point(
    t: &mut BN254Tracker,
    point_name: &str,
    x_name: &str,
    y_name: &str,
) {
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

    // Stack: [yName, xName] -- swap to standard order [xName, yName]
    t.swap();
}

/// bn254_compose_point: composes (x_num, y_num) into a 64-byte Point.
pub(crate) fn bn254_compose_point(
    t: &mut BN254Tracker,
    x_name: &str,
    y_name: &str,
    result_name: &str,
) {
    // Convert x to 32-byte big-endian
    t.to_top(x_name);
    t.raw_block(&[x_name], Some("_cp_xb"), |e| {
        e(StackOp::Push(PushValue::Int(33)));
        e(StackOp::Opcode("OP_NUM2BIN".into()));
        // Drop the sign byte (last byte) -- split at 32, keep left
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

// ===========================================================================
// Affine point addition (for bn254G1Add)
// ===========================================================================

/// bn254_g1_affine_add: affine point addition on BN254 G1.
/// Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
///
/// Uses the unified slope formula
///
/// ```text
/// s = (px^2 + px*qx + qx^2) / (py + qy)
/// ```
///
/// which works for both the addition case (P != Q) and the doubling case
/// (P == Q) on y^2 = x^3 + b.
pub(crate) fn bn254_g1_affine_add(t: &mut BN254Tracker) {
    // s_num = px^2 + px*qx + qx^2
    t.copy_to_top("px", "_px_sq_in");
    bn254_field_sqr(t, "_px_sq_in", "_px_sq");
    t.copy_to_top("px", "_px_m");
    t.copy_to_top("qx", "_qx_m");
    bn254_field_mul(t, "_px_m", "_qx_m", "_px_qx");
    t.copy_to_top("qx", "_qx_sq_in");
    bn254_field_sqr(t, "_qx_sq_in", "_qx_sq");
    bn254_field_add(t, "_px_sq", "_px_qx", "_s_num_tmp");
    bn254_field_add(t, "_s_num_tmp", "_qx_sq", "_s_num");

    // s_den = py + qy
    t.copy_to_top("py", "_py_a");
    t.copy_to_top("qy", "_qy_a");
    bn254_field_add(t, "_py_a", "_qy_a", "_s_den");

    // s = s_num / s_den mod p
    bn254_field_inv(t, "_s_den", "_s_den_inv");
    bn254_field_mul(t, "_s_num", "_s_den_inv", "_s");

    // rx = s^2 - px - qx mod p
    t.copy_to_top("_s", "_s_keep");
    bn254_field_sqr(t, "_s", "_s2");
    t.copy_to_top("px", "_px2");
    bn254_field_sub(t, "_s2", "_px2", "_rx1");
    t.copy_to_top("qx", "_qx2");
    bn254_field_sub(t, "_rx1", "_qx2", "rx");

    // ry = s * (px - rx) - py mod p
    t.copy_to_top("px", "_px3");
    t.copy_to_top("rx", "_rx2");
    bn254_field_sub(t, "_px3", "_rx2", "_px_rx");
    bn254_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx");
    t.copy_to_top("py", "_py2");
    bn254_field_sub(t, "_s_px_rx", "_py2", "ry");

    // Clean up original points
    t.to_top("px"); t.drop();
    t.to_top("py"); t.drop();
    t.to_top("qx"); t.drop();
    t.to_top("qy"); t.drop();
}

// ===========================================================================
// Jacobian point operations (for bn254G1ScalarMul)
// ===========================================================================

/// bn254_g1_jacobian_double: Jacobian point doubling (a=0 for BN254).
/// Expects jx, jy, jz on tracker. Replaces with updated values.
pub(crate) fn bn254_g1_jacobian_double(t: &mut BN254Tracker) {
    // Save copies of jx, jy, jz for later use
    t.copy_to_top("jy", "_jy_save");
    t.copy_to_top("jx", "_jx_save");
    t.copy_to_top("jz", "_jz_save");

    // A = jy^2
    bn254_field_sqr(t, "jy", "_A");

    // B = 4 * jx * A
    t.copy_to_top("_A", "_A_save");
    bn254_field_mul(t, "jx", "_A", "_xA");
    t.push_int("_four", 4);
    bn254_field_mul(t, "_xA", "_four", "_B");

    // C = 8 * A^2
    bn254_field_sqr(t, "_A_save", "_A2");
    t.push_int("_eight", 8);
    bn254_field_mul(t, "_A2", "_eight", "_C");

    // D = 3 * X^2
    bn254_field_sqr(t, "_jx_save", "_x2");
    t.push_int("_three", 3);
    bn254_field_mul(t, "_x2", "_three", "_D");

    // nx = D^2 - 2*B
    t.copy_to_top("_D", "_D_save");
    t.copy_to_top("_B", "_B_save");
    bn254_field_sqr(t, "_D", "_D2");
    t.copy_to_top("_B", "_B1");
    bn254_field_mul_const(t, "_B1", 2, "_2B");
    bn254_field_sub(t, "_D2", "_2B", "_nx");

    // ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy");
    bn254_field_sub(t, "_B_save", "_nx_copy", "_B_nx");
    bn254_field_mul(t, "_D_save", "_B_nx", "_D_B_nx");
    bn254_field_sub(t, "_D_B_nx", "_C", "_ny");

    // nz = 2 * Y * Z
    bn254_field_mul(t, "_jy_save", "_jz_save", "_yz");
    bn254_field_mul_const(t, "_yz", 2, "_nz");

    // Clean up leftovers: _B and old jz
    t.to_top("_B"); t.drop();
    t.to_top("jz"); t.drop();
    t.to_top("_nx"); t.rename("jx");
    t.to_top("_ny"); t.rename("jy");
    t.to_top("_nz"); t.rename("jz");
}

/// bn254_g1_jacobian_to_affine: Jacobian -> Affine conversion.
/// Consumes jx, jy, jz; produces rxName, ryName.
pub(crate) fn bn254_g1_jacobian_to_affine(
    t: &mut BN254Tracker,
    rx_name: &str,
    ry_name: &str,
) {
    bn254_field_inv(t, "jz", "_zinv");
    t.copy_to_top("_zinv", "_zinv_keep");
    bn254_field_sqr(t, "_zinv", "_zinv2");
    t.copy_to_top("_zinv2", "_zinv2_keep");
    bn254_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3");
    bn254_field_mul(t, "jx", "_zinv2_keep", rx_name);
    bn254_field_mul(t, "jy", "_zinv3", ry_name);
}

// ===========================================================================
// Jacobian mixed addition (P_jacobian + Q_affine)
// ===========================================================================

/// bn254_build_jacobian_add_affine_standard: emits the standard Jacobian mixed-add
/// sequence assuming the doubling case has already been excluded by the caller.
///
/// Consumes jx, jy, jz on the tracker (the affine base point ax, ay is read
/// via copy-to-top) and produces replacement jx, jy, jz.
///
/// WARNING: this function fails (H = 0 in the chord formula) when the
/// Jacobian accumulator equals the affine base point in affine form.
fn bn254_build_jacobian_add_affine_standard(it: &mut BN254Tracker) {
    // Save copies of values that get consumed but are needed later
    it.copy_to_top("jz", "_jz_for_z1cu"); // consumed by Z1sq, needed for Z1cu
    it.copy_to_top("jz", "_jz_for_z3");   // needed for Z3
    it.copy_to_top("jy", "_jy_for_y3");   // consumed by R, needed for Y3
    it.copy_to_top("jx", "_jx_for_u1h2"); // consumed by H, needed for U1H2

    // Z1sq = jz^2
    bn254_field_sqr(it, "jz", "_Z1sq");

    // Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2");
    bn254_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu");

    // U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c");
    bn254_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2");

    // S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c");
    bn254_field_mul(it, "_ay_c", "_Z1cu", "_S2");

    // H = U2 - jx
    bn254_field_sub(it, "_U2", "jx", "_H");

    // R = S2 - jy
    bn254_field_sub(it, "_S2", "jy", "_R");

    // Save copies of H
    it.copy_to_top("_H", "_H_for_h3");
    it.copy_to_top("_H", "_H_for_z3");

    // H2 = H^2
    bn254_field_sqr(it, "_H", "_H2");

    // Save H2 for U1H2
    it.copy_to_top("_H2", "_H2_for_u1h2");

    // H3 = H_for_h3 * H2
    bn254_field_mul(it, "_H_for_h3", "_H2", "_H3");

    // U1H2 = _jx_for_u1h2 * H2_for_u1h2
    bn254_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2");

    // Save R, U1H2, H3 for Y3 computation
    it.copy_to_top("_R", "_R_for_y3");
    it.copy_to_top("_U1H2", "_U1H2_for_y3");
    it.copy_to_top("_H3", "_H3_for_y3");

    // X3 = R^2 - H3 - 2*U1H2
    bn254_field_sqr(it, "_R", "_R2");
    bn254_field_sub(it, "_R2", "_H3", "_x3_tmp");
    bn254_field_mul_const(it, "_U1H2", 2, "_2U1H2");
    bn254_field_sub(it, "_x3_tmp", "_2U1H2", "_X3");

    // Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c");
    bn254_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x");
    bn254_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp");
    bn254_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3");
    bn254_field_sub(it, "_r_tmp", "_jy_h3", "_Y3");

    // Z3 = _jz_for_z3 * _H_for_z3
    bn254_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3");

    // Rename results to jx/jy/jz
    it.to_top("_X3"); it.rename("jx");
    it.to_top("_Y3"); it.rename("jy");
    it.to_top("_Z3"); it.rename("jz");
}

/// bn254_build_jacobian_add_affine_inline: doubling-safe wrapper around the
/// standard mixed-add. Checks H == 0 at runtime and branches to Jacobian
/// doubling on the accumulator when the mixed-add would otherwise divide by zero.
///
/// Stack layout: [..., ax, ay, _k, jx, jy, jz]
/// After:        [..., ax, ay, _k, jx', jy', jz']
fn bn254_build_jacobian_add_affine_inline(e: &mut dyn FnMut(StackOp), t: &BN254Tracker) {
    // Create inner tracker with cloned stack state
    let cloned_nm: Vec<String> = t.nm.clone();
    let mut it = BN254Tracker::new_from_strings(&cloned_nm, e);
    // Propagate prime cache state: the cached prime on the alt-stack is
    // accessible within OP_IF branches since alt-stack persists across
    // IF/ELSE/ENDIF boundaries.
    it.prime_cache_active = t.prime_cache_active;

    // ------------------------------------------------------------------
    // Doubling-case detection: H = ax*jz^2 - jx == 0 ?
    // ------------------------------------------------------------------
    // Compute U2 = ax * jz^2 without consuming jx, jy, or jz, then
    // compare against a fresh copy of jx. Consumes only the copies.
    it.copy_to_top("jz", "_jz_chk_in");
    bn254_field_sqr(&mut it, "_jz_chk_in", "_jz_chk_sq");
    it.copy_to_top("ax", "_ax_chk_copy");
    bn254_field_mul(&mut it, "_ax_chk_copy", "_jz_chk_sq", "_u2_chk");
    it.copy_to_top("jx", "_jx_chk_copy");
    it.raw_block(&["_u2_chk", "_jx_chk_copy"], Some("_h_is_zero"), |e| {
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
    });

    // Move _h_is_zero to top so OP_IF can consume it.
    it.to_top("_h_is_zero");
    it.nm.pop(); // consumed by IF

    // ------------------------------------------------------------------
    // Gather doubling-branch ops
    // ------------------------------------------------------------------
    let doubling_nm = it.nm.clone();
    let doubling_ops = {
        let mut ops: Vec<StackOp> = Vec::new();
        {
            let mut doubling_emit = |op: StackOp| ops.push(op);
            let mut doubling_tracker = BN254Tracker::new_from_strings(&doubling_nm, &mut doubling_emit);
            doubling_tracker.prime_cache_active = it.prime_cache_active;
            bn254_g1_jacobian_double(&mut doubling_tracker);
        }
        ops
    };

    // ------------------------------------------------------------------
    // Gather standard-add-branch ops
    // ------------------------------------------------------------------
    let add_nm = it.nm.clone();
    let (add_ops, final_nm) = {
        let mut ops: Vec<StackOp> = Vec::new();
        let final_nm;
        {
            let mut add_emit = |op: StackOp| ops.push(op);
            let mut add_tracker = BN254Tracker::new_from_strings(&add_nm, &mut add_emit);
            add_tracker.prime_cache_active = it.prime_cache_active;
            bn254_build_jacobian_add_affine_standard(&mut add_tracker);
            final_nm = add_tracker.nm.clone();
        }
        (ops, final_nm)
    };

    // Both branches leave (jx, jy, jz) replacing the originals with the
    // same stack layout.
    (it.e)(StackOp::If {
        then_ops: doubling_ops,
        else_ops: add_ops,
    });
    it.nm = final_nm;
}

// ===========================================================================
// G1 point negation
// ===========================================================================

/// bn254_g1_negate: negates a point: (x, p - y).
pub(crate) fn bn254_g1_negate(t: &mut BN254Tracker, point_name: &str, result_name: &str) {
    bn254_decompose_point(t, point_name, "_nx", "_ny");
    // Use bn254_field_neg which already handles prime caching
    bn254_field_neg(t, "_ny", "_neg_y");
    bn254_compose_point(t, "_nx", "_neg_y", result_name);
}

// ===========================================================================
// Public emit functions -- entry points called from stack.rs
// ===========================================================================

/// emit_bn254_field_add: BN254 field addition.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a + b) mod p]
pub fn emit_bn254_field_add(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["a", "b"], emit);
    t.push_prime_cache();
    bn254_field_add(&mut t, "a", "b", "result");
    t.pop_prime_cache();
}

/// emit_bn254_field_sub: BN254 field subtraction.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a - b) mod p]
pub fn emit_bn254_field_sub(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["a", "b"], emit);
    t.push_prime_cache();
    bn254_field_sub(&mut t, "a", "b", "result");
    t.pop_prime_cache();
}

/// emit_bn254_field_mul: BN254 field multiplication.
/// Stack in: [..., a, b] (b on top)
/// Stack out: [..., (a * b) mod p]
pub fn emit_bn254_field_mul(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["a", "b"], emit);
    t.push_prime_cache();
    bn254_field_mul(&mut t, "a", "b", "result");
    t.pop_prime_cache();
}

/// emit_bn254_field_inv: BN254 field multiplicative inverse.
/// Stack in: [..., a]
/// Stack out: [..., a^(p-2) mod p]
pub fn emit_bn254_field_inv(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["a"], emit);
    t.push_prime_cache();
    bn254_field_inv(&mut t, "a", "result");
    t.pop_prime_cache();
}

/// emit_bn254_field_neg: BN254 field negation.
/// Stack in: [..., a]
/// Stack out: [..., (p - a) mod p]
pub fn emit_bn254_field_neg(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["a"], emit);
    t.push_prime_cache();
    bn254_field_neg(&mut t, "a", "result");
    t.pop_prime_cache();
}

/// emit_bn254_g1_add: adds two BN254 G1 points.
/// Stack in: [point_a, point_b] (b on top)
/// Stack out: [result_point]
pub fn emit_bn254_g1_add(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["_pa", "_pb"], emit);
    t.push_prime_cache();
    bn254_decompose_point(&mut t, "_pa", "px", "py");
    bn254_decompose_point(&mut t, "_pb", "qx", "qy");
    bn254_g1_affine_add(&mut t);
    bn254_compose_point(&mut t, "rx", "ry", "_result");
    t.pop_prime_cache();
}

/// emit_bn254_g1_scalar_mul: scalar multiplication P * k on BN254 G1.
/// Stack in: [point, scalar] (scalar on top)
/// Stack out: [result_point]
///
/// Uses 255-iteration double-and-add with Jacobian coordinates.
/// k' = k + 3*r guarantees bit 255 is set (r is the curve order).
pub fn emit_bn254_g1_scalar_mul(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["_pt", "_k"], emit);
    t.push_prime_cache();
    // Decompose to affine base point
    bn254_decompose_point(&mut t, "_pt", "ax", "ay");

    // k' = k + 3r: guarantees bit 255 is set.
    t.to_top("_k");
    t.push_curve_r("_r1");
    t.raw_block(&["_k", "_r1"], Some("_kr1"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_curve_r("_r2");
    t.raw_block(&["_kr1", "_r2"], Some("_kr2"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_curve_r("_r3");
    t.raw_block(&["_kr2", "_r3"], Some("_kr3"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.rename("_k");

    // Init accumulator = P (bit 255 of k+3r is always 1)
    t.copy_to_top("ax", "jx");
    t.copy_to_top("ay", "jy");
    t.push_int("jz", 1);

    // 255 iterations: bits 254 down to 0
    for bit in (0..=254i32).rev() {
        // Double accumulator
        bn254_g1_jacobian_double(&mut t);

        // Extract bit: (k >> bit) & 1
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
        let add_ops = collect_ops(|add_emit| {
            bn254_build_jacobian_add_affine_inline(add_emit, &t);
        });
        (t.e)(StackOp::If {
            then_ops: add_ops,
            else_ops: vec![],
        });
    }

    // Convert Jacobian to affine
    bn254_g1_jacobian_to_affine(&mut t, "_rx", "_ry");

    // Clean up base point and scalar
    t.to_top("ax"); t.drop();
    t.to_top("ay"); t.drop();
    t.to_top("_k"); t.drop();

    // Compose result
    bn254_compose_point(&mut t, "_rx", "_ry", "_result");
    t.pop_prime_cache();
}

/// emit_bn254_g1_negate: negates a BN254 G1 point (x, p - y).
/// Stack in: [point]
/// Stack out: [negated_point]
pub fn emit_bn254_g1_negate(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["_pt"], emit);
    t.push_prime_cache();
    bn254_g1_negate(&mut t, "_pt", "_result");
    t.pop_prime_cache();
}

/// emit_bn254_g1_on_curve: checks if point is on BN254 G1 (y^2 = x^3 + 3 mod p).
/// Stack in: [point]
/// Stack out: [boolean]
pub fn emit_bn254_g1_on_curve(emit: &mut dyn FnMut(StackOp)) {
    let mut t = BN254Tracker::new(&["_pt"], emit);
    t.push_prime_cache();
    bn254_decompose_point(&mut t, "_pt", "_x", "_y");

    // lhs = y^2
    bn254_field_sqr(&mut t, "_y", "_y2");

    // rhs = x^3 + 3
    t.copy_to_top("_x", "_x_copy");
    bn254_field_sqr(&mut t, "_x", "_x2");
    bn254_field_mul(&mut t, "_x2", "_x_copy", "_x3");
    t.push_int("_three", 3); // b = 3 for BN254
    bn254_field_add(&mut t, "_x3", "_three", "_rhs");

    // Compare
    t.to_top("_y2");
    t.to_top("_rhs");
    t.raw_block(&["_y2", "_rhs"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_EQUAL".into()));
    });
    t.pop_prime_cache();
}
