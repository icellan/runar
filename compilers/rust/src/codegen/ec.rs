//! EC codegen — secp256k1 elliptic curve operations for Bitcoin Script.
//!
//! Port of packages/runar-compiler/src/passes/ec-codegen.ts.
//! All helpers are self-contained.
//!
//! Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
//! Internal arithmetic uses Jacobian coordinates for scalar multiplication.

use num_bigint::BigInt;
use std::sync::LazyLock;
use num_traits::ToPrimitive;
use super::stack::{PushValue, StackOp};
use super::cost_model::{estimate_script_bytes, size_of_push_int};
use super::comb::{comb_geometry, comb_safe_rounds, comb_table, SECP256K1_COMB_CURVE};

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

/// Codegen options shared by every EC / NIST-curve emitter.
///
/// Off by default: with `None` (or an all-false struct) each emitter is
/// byte-identical to what the seven tiers ship today, so no golden, size
/// baseline, or cross-tier parity gate can move.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EcCodegenOptions {
    /// Park large repeated constants (the field prime, the group order) in a
    /// stack slot and copy them with `OP_PICK` instead of re-pushing the
    /// literal.
    ///
    /// `field_mod` pushes the 256-bit prime at every modular reduction — 34
    /// bytes a time, 20,025 times in `p256-wallet` (71 % of that fixture). A
    /// pick from a slot a dozen deep costs 2.
    pub constant_pool: bool,

    /// Emit `a mod p` without the sign fix-up wherever the dividend is provably
    /// non-negative, and the cheap `a - b + p` form for subtraction wherever the
    /// subtrahend is provably reduced.
    ///
    /// Which reductions qualify is decided by the sign lattice below — never
    /// assumed. Only useful alongside `constant_pool`: the cheap subtraction
    /// references the prime twice, so without a pooled slot it does not pay (and
    /// the emitters compare the two costs, so it is never taken when it does
    /// not).
    pub reduction_sinking: bool,

    /// Use a fixed-base comb instead of the binary ladder wherever the base
    /// point is a compile-time constant (`ecMulGen`, `p256MulGen`,
    /// `p384MulGen`, and the `u1·G` half of ECDSA verification).
    ///
    /// The window width is not fixed here: the emitter renders each candidate
    /// and keeps whichever the byte-cost model scores smallest.
    pub fixed_base_comb: bool,
}

/// What is known about a tracked value's sign and range.
///
/// `Reduced` implies `NonNegative`; the ordering is what the transfer functions
/// meet over. `Unknown` is the default for every slot the analysis has not
/// explicitly proved something about — including everything a `raw_block` or an
/// `OP_IF` produces — so an un-analysed value can only ever fall back to the
/// shipping reduction.
///
/// The distinction is not academic. `OP_BIN2NUM` of 32 unsigned coordinate bytes
/// gives `NonNegative` but NOT `Reduced`: a coordinate may legitimately be up to
/// `2^256 - 1` while p is `2^32 + 977` smaller. Multiplication and addition need
/// only `NonNegative`; subtraction's cheap form needs the subtrahend `Reduced`,
/// and conflating the two produces a script that passes 256 EC oracle assertions
/// and is still wrong on `ecAdd((0,1), (2^256-1,1))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Dom {
    /// Nothing known. May be negative.
    #[default]
    Unknown,
    /// Provably >= 0. May be >= p.
    NonNegative,
    /// Provably in [0, p).
    Reduced,
}

impl Dom {
    /// True when this proves the value is >= 0.
    pub(crate) fn is_non_negative(self) -> bool {
        self >= Dom::NonNegative
    }
}

/// Stack slot names reserved for pooled constants.
pub const POOL_FIELD_P: &str = "_pool$p";
pub const POOL_GROUP_N: &str = "_pool$n";

pub(crate) struct ECTracker<'a> {
    pub(crate) nm: Vec<String>,
    /// Sign-lattice fact per stack SLOT, kept parallel to `nm`.
    ///
    /// Slot-parallel rather than keyed by name on purpose: names are reused
    /// (`_fmul_prod` is written by every multiply) and the same name can be
    /// resident twice, so a name-keyed map would go stale in exactly the cases
    /// that matter. Every mutation of `nm` below mirrors into `dm` with the same
    /// splice, so the two cannot drift.
    pub(crate) dm: Vec<Dom>,
    /// Lattice facts for values parked on the alt stack, bottom -> top.
    alt_dm: Vec<Dom>,
    pub(crate) e: &'a mut dyn FnMut(StackOp),
    /// True when this tracker may serve constants from a pooled slot.
    pub(crate) pooling: bool,
    /// True when this tracker may emit sunk reductions.
    pub(crate) sinking: bool,
    /// True when a compile-time-known base may use a fixed-base comb.
    pub(crate) comb: bool,
}

#[allow(dead_code)]
impl<'a> ECTracker<'a> {
    pub(crate) fn new(init: &[&str], emit: &'a mut dyn FnMut(StackOp)) -> Self {
        Self::with_opts(init, emit, None, None)
    }

    /// Create a tracker carrying codegen options and, optionally, initial
    /// lattice facts for the pre-existing slots.
    pub(crate) fn with_opts(
        init: &[&str],
        emit: &'a mut dyn FnMut(StackOp),
        opts: Option<&EcCodegenOptions>,
        init_domains: Option<&[Dom]>,
    ) -> Self {
        let nm: Vec<String> = init.iter().map(|s| s.to_string()).collect();
        let dm: Vec<Dom> = match init_domains {
            Some(d) => d.to_vec(),
            None => vec![Dom::Unknown; nm.len()],
        };
        let o = opts.copied().unwrap_or_default();
        ECTracker {
            nm,
            dm,
            alt_dm: Vec::new(),
            e: emit,
            pooling: o.constant_pool,
            sinking: o.reduction_sinking,
            comb: o.fixed_base_comb,
        }
    }

    /// The options this tracker was built with, for handing to a nested tracker.
    pub(crate) fn options(&self) -> EcCodegenOptions {
        EcCodegenOptions {
            constant_pool: self.pooling,
            reduction_sinking: self.sinking,
            fixed_base_comb: self.comb,
        }
    }

    // -- sign lattice --------------------------------------------------------

    /// What is known about the named value. `Unknown` when the name is absent.
    pub(crate) fn domain_of(&self, name: &str) -> Dom {
        // A silent desync here would hand a transfer function a fact about the
        // WRONG slot, which is the one failure mode that produces a smaller
        // script that quietly computes something else. Fail loudly instead.
        assert_eq!(
            self.dm.len(),
            self.nm.len(),
            "ECTracker: lattice desynchronised. Every nm mutation must go through \
             a tracker method or push_tracked/pop_tracked."
        );
        for i in (0..self.nm.len()).rev() {
            if self.nm[i] == name {
                return self.dm[i];
            }
        }
        Dom::Unknown
    }

    /// Record a fact about the named value's slot.
    pub(crate) fn set_domain(&mut self, name: &str, d: Dom) {
        for i in (0..self.nm.len()).rev() {
            if self.nm[i] == name {
                self.dm[i] = d;
                return;
            }
        }
    }

    /// Push a slot the caller tracks itself (used where raw opcodes create items).
    pub(crate) fn push_tracked(&mut self, name: &str, d: Dom) {
        self.nm.push(name.to_string());
        self.dm.push(d);
    }

    /// Pop a slot the caller tracks itself. Mirror of `push_tracked`.
    pub(crate) fn pop_tracked(&mut self) -> Option<String> {
        self.dm.pop();
        self.nm.pop()
    }

    /// Remove the slot at an absolute (bottom-relative) index.
    pub(crate) fn remove_slot_at(&mut self, index: usize) -> (String, Dom) {
        (self.nm.remove(index), self.dm.remove(index))
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
        panic!("ECTracker: '{}' not on stack {:?}", name, self.nm);
    }

    pub(crate) fn push_bytes(&mut self, n: &str, v: Vec<u8>) {
        (self.e)(StackOp::Push(PushValue::Bytes(v)));
        // A byte blob is not a number until BIN2NUM decides how to read it.
        self.push_tracked(n, Dom::Unknown);
    }

    pub(crate) fn push_int(&mut self, n: &str, v: i128) {
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(v))));
        self.push_tracked(n, if v >= 0 { Dom::NonNegative } else { Dom::Unknown });
    }

    /// Push an arbitrary-precision integer.
    ///
    /// The EC constants exceed `i128`, and the tier used to push them as
    /// pre-encoded script-number BYTE blobs. Encoded hex is identical either
    /// way, but a `Bytes` push is invisible to the peephole's constant folding
    /// and to the lattice, so a repeated constant could neither be folded nor
    /// proved non-negative. Pushing them as `Int` restores both.
    pub(crate) fn push_big(&mut self, n: &str, v: &BigInt) {
        (self.e)(StackOp::Push(PushValue::Int(v.clone())));
        let d = if v.sign() == num_bigint::Sign::Minus { Dom::Unknown } else { Dom::NonNegative };
        self.push_tracked(n, d);
    }

    pub(crate) fn dup(&mut self, n: &str) {
        (self.e)(StackOp::Dup);
        let d = self.dm.last().copied().unwrap_or_default();
        self.push_tracked(n, d);
    }

    pub(crate) fn drop(&mut self) {
        (self.e)(StackOp::Drop);
        self.pop_tracked();
    }

    pub(crate) fn nip(&mut self) {
        (self.e)(StackOp::Nip);
        let len = self.nm.len();
        if len >= 2 {
            self.remove_slot_at(len - 2);
        }
    }

    pub(crate) fn over(&mut self, n: &str) {
        (self.e)(StackOp::Over);
        let d = if self.dm.len() >= 2 { self.dm[self.dm.len() - 2] } else { Dom::Unknown };
        self.push_tracked(n, d);
    }

    pub(crate) fn swap(&mut self) {
        (self.e)(StackOp::Swap);
        let len = self.nm.len();
        if len >= 2 {
            self.nm.swap(len - 1, len - 2);
            self.dm.swap(len - 1, len - 2);
        }
    }

    pub(crate) fn rot(&mut self) {
        (self.e)(StackOp::Rot);
        let len = self.nm.len();
        if len >= 3 {
            let (r, rd) = self.remove_slot_at(len - 3);
            self.push_tracked(&r, rd);
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
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
        self.push_tracked("", Dom::NonNegative);
        (self.e)(StackOp::Opcode("OP_ROLL".into()));
        self.pop_tracked(); // the depth literal
        let idx = self.nm.len() - 1 - d;
        let (r, rd) = self.remove_slot_at(idx);
        self.push_tracked(&r, rd);
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
        (self.e)(StackOp::Push(PushValue::Int(BigInt::from(d as i128))));
        self.push_tracked("", Dom::NonNegative);
        (self.e)(StackOp::Opcode("OP_PICK".into()));
        self.pop_tracked(); // the depth literal
        // Once the depth literal is gone the copied slot sits at depth d.
        let src = if self.dm.len() > d { self.dm[self.dm.len() - 1 - d] } else { Dom::Unknown };
        self.push_tracked(n, src);
    }

    pub(crate) fn to_top(&mut self, name: &str) {
        let d = self.find_depth(name);
        self.roll(d);
    }

    pub(crate) fn copy_to_top(&mut self, name: &str, n: &str) {
        let d = self.find_depth(name);
        self.pick(d, n);
    }

    // -- constant pool -------------------------------------------------------
    //
    // A pooled constant is an ordinary tracked slot; nothing about the stack
    // model changes. `push_const` just chooses, per call site and by emitted
    // bytes, between copying that slot and re-pushing the literal. Nested
    // trackers built from `nm.clone()` inherit the slot for free, so pooled
    // constants work unchanged inside an `OP_IF` arm.

    pub(crate) fn has_slot(&self, slot: &str) -> bool {
        self.nm.iter().any(|n| n == slot)
    }

    /// Park `value` in `slot` for the lifetime of this emitter. No-op when
    /// pooling is off.
    pub(crate) fn pool_constant(&mut self, slot: &str, value: &BigInt) {
        if !self.pooling || self.has_slot(slot) {
            return;
        }
        self.push_big(slot, value);
    }

    /// Remove a pooled slot. No-op when pooling is off or the slot is absent.
    pub(crate) fn release_constant(&mut self, slot: &str) {
        if !self.pooling || !self.has_slot(slot) {
            return;
        }
        self.to_top(slot);
        self.drop();
    }

    /// Emitted bytes a `push_const` of this constant would cost right now.
    ///
    /// The comparison is exact — `size_of_push_int` is the same encoder the emit
    /// pass uses — so pooling can never make a call site bigger. A pick at depth
    /// d costs `size_of_push_int(d) + 1`; depths 0 and 1 are OP_DUP / OP_OVER, 1
    /// byte each.
    pub(crate) fn const_cost(&self, slot: &str, value: &BigInt) -> usize {
        if self.pooling && self.has_slot(slot) {
            let d = self.find_depth(slot);
            let pick_cost = if d <= 1 { 1 } else { size_of_push_int(&BigInt::from(d)) + 1 };
            if pick_cost < size_of_push_int(value) {
                return pick_cost;
            }
        }
        size_of_push_int(value)
    }

    /// Materialize `value` on top as `name`, from the pooled `slot` when that is
    /// cheaper in emitted bytes than pushing the literal.
    pub(crate) fn push_const(&mut self, slot: &str, value: &BigInt, name: &str) {
        if self.pooling && self.has_slot(slot) {
            let d = self.find_depth(slot);
            let pick_cost = if d <= 1 { 1 } else { size_of_push_int(&BigInt::from(d)) + 1 };
            if pick_cost < size_of_push_int(value) {
                self.pick(d, name);
                return;
            }
        }
        self.push_big(name, value);
    }

    pub(crate) fn to_alt(&mut self) {
        self.op("OP_TOALTSTACK");
        if !self.nm.is_empty() {
            let d = self.dm[self.dm.len() - 1];
            self.pop_tracked();
            self.alt_dm.push(d);
        }
    }

    pub(crate) fn from_alt(&mut self, n: &str) {
        self.op("OP_FROMALTSTACK");
        let d = self.alt_dm.pop().unwrap_or_default();
        self.push_tracked(n, d);
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
            self.pop_tracked();
        }
        f(self.e);
        if let Some(p) = produce {
            // Opaque opcodes: nothing is known about the result unless the
            // caller proves it and records that with `set_domain` afterwards.
            self.push_tracked(p, Dom::Unknown);
        }
    }

    /// Emit if/else with tracked stack effect.
    pub(crate) fn emit_if(
        &mut self,
        cond_name: &str,
        then_fn: impl FnOnce(&mut dyn FnMut(StackOp)),
        else_fn: impl FnOnce(&mut dyn FnMut(StackOp)),
        result_name: Option<&str>,
    ) {
        self.to_top(cond_name);
        self.pop_tracked(); // condition consumed
        let then_ops = collect_ops(then_fn);
        let else_ops = collect_ops(else_fn);
        (self.e)(StackOp::If {
            then_ops,
            else_ops,
        });
        if let Some(rn) = result_name {
            // A join over two arms this tracker did not analyse: nothing is known.
            self.push_tracked(rn, Dom::Unknown);
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

/// secp256k1 field prime p, as an integer.
///
/// The tier used to push this (and the group order) as a pre-encoded
/// script-number BYTE blob, because the value exceeds `i128`. `PushValue::Int`
/// carries a `BigInt`, so the blob was never necessary — and it cost real
/// things: a `Bytes` push is invisible to the peephole's constant folding (which
/// is why the `+3n` chain had to be pre-folded by hand) and to the sign lattice.
pub(crate) static FIELD_P: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16).unwrap()
});

/// secp256k1 curve order n.
pub(crate) static CURVE_N: LazyLock<BigInt> = LazyLock::new(|| {
    BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap()
});

/// Push the field prime p onto the stack as a script number.
fn push_field_p(t: &mut ECTracker, name: &str) {
    t.push_const(POOL_FIELD_P, &FIELD_P, name);
}

/// `a mod p` with no sign fix-up: 1 opcode instead of 7.
///
/// Sound only when the dividend is provably >= 0, because `OP_MOD` takes the
/// sign of the dividend. The caller proves that; this function does not check.
fn field_mod_short(t: &mut ECTracker, a_name: &str, result_name: &str) {
    t.to_top(a_name);
    push_field_p(t, "_fmods_p");
    t.raw_block(&[a_name, "_fmods_p"], Some(result_name), |e| {
        e(StackOp::Opcode("OP_MOD".into()));
    });
    t.set_domain(result_name, Dom::Reduced);
}

/// Does the cheap `a - b + p` subtraction shape pay here?
///
/// It references the prime TWICE where the shipping shape references it once and
/// pays six more opcodes, so it only wins when the prime is cheap to
/// materialise — i.e. when it is pooled. Without a pool this rewrite makes
/// p256-wallet LARGER (958,792 -> 999,371 measured), which is why it is a cost
/// comparison and not a flag.
fn cheap_sub_pays(t: &ECTracker) -> bool {
    let c = t.const_cost(POOL_FIELD_P, &FIELD_P);
    2 * c + 2 < c + 8
}

/// fieldMod: reduce TOS mod p, ensure non-negative.
/// Expects `a_name` to be on the tracker stack.
fn field_mod(t: &mut ECTracker, a_name: &str, result_name: &str) {
    if t.sinking && t.domain_of(a_name).is_non_negative() {
        field_mod_short(t, a_name, result_name);
        return;
    }
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
    t.set_domain(result_name, Dom::Reduced);
}

/// fieldAdd: (a + b) mod p.
fn field_add(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    // Read the operand facts BEFORE raw_block consumes their slots.
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
    field_mod(t, "_fadd_sum", result_name);
}

/// fieldSub: (a - b) mod p (non-negative).
fn field_sub(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    t.to_top(a_name);
    t.to_top(b_name);
    // The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a single
    // shifted reduction is exact. `b >= 0` alone is NOT enough — a coordinate
    // decoded from 32 unsigned bytes can exceed p by up to 2^32 + 977, which is
    // precisely the `ecAdd((0,1), (2^256-1,1))` counterexample.
    let cheap = t.sinking
        && t.domain_of(a_name).is_non_negative()
        && t.domain_of(b_name) == Dom::Reduced
        && cheap_sub_pays(t);

    t.raw_block(&[a_name, b_name], Some("_fsub_diff"), |e| {
        e(StackOp::Opcode("OP_SUB".into()));
    });

    if cheap {
        push_field_p(t, "_fsub_p");
        t.raw_block(&["_fsub_diff", "_fsub_p"], Some("_fsub_shift"), |e| {
            e(StackOp::Opcode("OP_ADD".into()));
        });
        t.set_domain("_fsub_shift", Dom::NonNegative);
        field_mod_short(t, "_fsub_shift", result_name);
        return;
    }
    field_mod(t, "_fsub_diff", result_name);
}

/// fieldMul: (a * b) mod p.
fn field_mul(t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str) {
    field_mul_signed(t, a_name, b_name, result_name, false);
}

/// `field_mul` with an explicit assertion about the product's sign, independent
/// of the operands — `field_sqr` uses it, since a*a >= 0 for any a whatsoever.
fn field_mul_signed(
    t: &mut ECTracker, a_name: &str, b_name: &str, result_name: &str,
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
    field_mod(t, "_fmul_prod", result_name);
}

/// fieldMulConst: (a * c) mod p where c is a small constant.
fn field_mul_const(t: &mut ECTracker, a_name: &str, c: i128, result_name: &str) {
    // Every call site passes a small positive c, so the product keeps a's sign.
    let non_neg = c > 0 && t.domain_of(a_name).is_non_negative();
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
    if non_neg {
        t.set_domain("_fmc_prod", Dom::NonNegative);
    }
    field_mod(t, "_fmc_prod", result_name);
}

/// fieldSqr: (a * a) mod p. A square is non-negative whatever a's sign is.
fn field_sqr(t: &mut ECTracker, a_name: &str, result_name: &str) {
    t.copy_to_top(a_name, "_fsqr_copy");
    field_mul_signed(t, a_name, "_fsqr_copy", result_name, true);
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
        e(StackOp::Push(PushValue::Int(BigInt::from(32))));
        e(StackOp::Opcode("OP_SPLIT".into()));
    });
    // Manually track the two new items
    t.push_tracked("_dp_xb", Dom::Unknown);
    t.push_tracked("_dp_yb", Dom::Unknown);

    // Convert y_bytes (on top) to num
    // Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
    t.raw_block(&["_dp_yb"], Some(y_name), |e| {
        emit_reverse_32(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });
    // A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    // UNSIGNED: >= 0, but it may be up to 2^256 - 1 and therefore >= p. That gap
    // is exactly what the subtraction precondition turns on.
    t.set_domain(y_name, Dom::NonNegative);

    // Convert x_bytes to num
    t.to_top("_dp_xb");
    t.raw_block(&["_dp_xb"], Some(x_name), |e| {
        emit_reverse_32(e);
        e(StackOp::Push(PushValue::Bytes(vec![0x00])));
        e(StackOp::Opcode("OP_CAT".into()));
        e(StackOp::Opcode("OP_BIN2NUM".into()));
    });
    t.set_domain(x_name, Dom::NonNegative);

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
    // Create the inner tracker with cloned stack state AND lattice facts: the
    // operands' proved domains are what decide which reduction shape the body
    // emits, so dropping them here would silently fall back everywhere.
    let cloned_nm: Vec<String> = t.nm.clone();
    let init_strs: Vec<&str> = cloned_nm.iter().map(|s| s.as_str()).collect();
    let opts = t.options();
    let mut it = ECTracker::with_opts(&init_strs, e, Some(&opts), Some(&t.dm));
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
    let opts = t.options();
    let mut it = ECTracker::with_opts(&init_strs, e, Some(&opts), Some(&t.dm));
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
pub fn emit_ec_add(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pa", "_pb"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &FIELD_P);
    decompose_point(&mut t, "_pa", "px", "py");
    decompose_point(&mut t, "_pb", "qx", "qy");
    affine_add(&mut t);
    compose_point(&mut t, "rx", "ry", "_result");
    t.release_constant(POOL_FIELD_P);
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
    t.push_const(POOL_GROUP_N, &CURVE_N, "_n_red");
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
pub fn emit_ec_mul(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt", "_k"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &FIELD_P);
    t.pool_constant(POOL_GROUP_N, &CURVE_N);
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
    // THREE separate `+n` steps, not a pre-folded `3n`. The peephole's
    // fold-chain-add collapses them back to the same `push 3n, ADD`, so the
    // shipped bytes are unchanged — but the pre-peephole form now matches the
    // reference, and each step can come from the pooled slot.
    t.push_const(POOL_GROUP_N, &CURVE_N, "_n");
    t.raw_block(&["_kr", "_n"], Some("_kn"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_const(POOL_GROUP_N, &CURVE_N, "_n2");
    t.raw_block(&["_kn", "_n2"], Some("_kn2"), |e| {
        e(StackOp::Opcode("OP_ADD".into()));
    });
    t.push_const(POOL_GROUP_N, &CURVE_N, "_n3");
    t.raw_block(&["_kn2", "_n3"], Some("_kn3"), |e| {
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
        t.pop_tracked(); // _bit consumed by IF
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
    t.release_constant(POOL_GROUP_N);
    t.release_constant(POOL_FIELD_P);
}


// ===========================================================================
// Fixed-base comb (secp256k1)
// ===========================================================================

/// Round `i`'s digit and the selected table entry, as `ax`/`ay`/`_flag`.
///
/// Exactly one equality holds, so `Σ eq_j · T_j` is that entry's coordinate and
/// every term is non-negative and below p — no reduction is needed, and the
/// result is `Reduced` by construction. When the digit is zero every term
/// vanishes and `_flag` is 0, so no add runs.
///
/// Shared by both comb emitters: the selection is pure scalar bit-twiddling and
/// table indexing, with no curve arithmetic in it at all.
pub(crate) fn comb_emit_select(t: &mut ECTracker, i: usize, w: usize, d: usize) {
    let entries = (1usize << w) - 1;
    for b in 0..w {
        let shift = i + b * d;
        let kc = format!("_kc{}", b);
        let sh = format!("_sh{}", b);
        t.copy_to_top("_k", &kc);
        if shift == 0 {
            t.rename(&sh);
        } else if shift == 1 {
            t.raw_block(&[&kc], Some(&sh), |e| {
                e(StackOp::Opcode("OP_2DIV".into()));
            });
        } else {
            let sd = format!("_sd{}", b);
            t.push_int(&sd, shift as i128);
            t.raw_block(&[&kc, &sd], Some(&sh), |e| {
                e(StackOp::Opcode("OP_RSHIFTNUM".into()));
            });
        }
        let two = format!("_two{}", b);
        let bit = format!("_b{}", b);
        t.push_int(&two, 2);
        t.raw_block(&[&sh, &two], Some(&bit), |e| {
            e(StackOp::Opcode("OP_MOD".into()));
        });
        t.set_domain(&bit, Dom::Reduced);
    }

    t.to_top("_b0");
    t.rename("_idx");
    for b in 1..w {
        let bit = format!("_b{}", b);
        let wt = format!("_wt{}", b);
        let bw = format!("_bw{}", b);
        t.to_top(&bit);
        t.push_int(&wt, 1i128 << b);
        t.raw_block(&[&bit, &wt], Some(&bw), |e| {
            e(StackOp::Opcode("OP_MUL".into()));
        });
        t.to_top("_idx");
        t.raw_block(&[&bw, "_idx"], Some("_idx"), |e| {
            e(StackOp::Opcode("OP_ADD".into()));
        });
    }
    t.set_domain("_idx", Dom::Reduced);

    for j in 1..=entries {
        let ic = format!("_ic{}", j);
        let jv = format!("_jv{}", j);
        let eq = format!("_eq{}", j);
        t.copy_to_top("_idx", &ic);
        t.push_int(&jv, j as i128);
        t.raw_block(&[&ic, &jv], Some(&eq), |e| {
            e(StackOp::Opcode("OP_NUMEQUAL".into()));
        });
        t.set_domain(&eq, Dom::Reduced);
    }

    for coord in ["x", "y"] {
        let acc = if coord == "x" { "ax" } else { "ay" };
        for j in 1..=entries {
            let ec = format!("_e{}{}", coord, j);
            let tc = format!("_t{}{}", coord, j);
            let pr = format!("_pr{}{}", coord, j);
            t.copy_to_top(&format!("_eq{}", j), &ec);
            t.copy_to_top(&format!("_T{}{}", coord, j), &tc);
            t.raw_block(&[&ec, &tc], Some(&pr), |e| {
                e(StackOp::Opcode("OP_MUL".into()));
            });
            if j == 1 {
                t.rename(acc);
            } else {
                t.to_top(acc);
                t.raw_block(&[&pr, acc], Some(acc), |e| {
                    e(StackOp::Opcode("OP_ADD".into()));
                });
            }
        }
        t.set_domain(acc, Dom::Reduced);
    }

    for j in (1..=entries).rev() {
        t.to_top(&format!("_eq{}", j));
        t.drop();
    }

    t.to_top("_idx");
    t.raw_block(&["_idx"], Some("_flag"), |e| {
        e(StackOp::Opcode("OP_0NOTEQUAL".into()));
    });
}

/// `k·G` by a Lim-Lee fixed-base comb instead of the 257-round binary ladder.
///
/// The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits
/// the scalar into `w` blocks of `d` bits and reads one bit from each block per
/// round, so it performs one doubling and one conditional add per COLUMN: the
/// round count falls from `w*d` to `d` at the price of a `2^w - 1` entry table.
/// G is a compile-time constant here, so the table costs nothing to build.
///
/// This is the secp256k1 twin of `c_emit_comb_mul_gen` in `p256_p384.rs`. The
/// curve arithmetic is NOT shared: secp256k1 has `a = 0`, so `jacobian_double`
/// computes `D = 3X²` where the NIST version computes `3(X-Z²)(X+Z²)`. Only
/// `comb.rs` — the compile-time table and the interval checker — is common, and
/// it takes `a` from the curve record rather than assuming it.
///
/// SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
/// accumulator equal to the addend, its negation, or the point at infinity.
/// `build_jacobian_add_or_double_inline`'s comment justifies using it everywhere
/// but the ladder's LAST step by an interval argument over `c_i mod n`, and
/// insists that argument be re-derived by anything changing the offset or the
/// iteration count. A comb changes both, so it is re-derived: `comb_safe_rounds`
/// evaluates the same argument as executable interval arithmetic over the comb's
/// own geometry, and any round it cannot prove gets the complete add-or-double
/// form instead. Nothing is assumed safe.
///
/// The other half of that argument is that the accumulator never starts at
/// infinity, which needs the first digit non-zero. `comb_geometry` searches for
/// the scalar offset that guarantees it rather than reusing the ladder's
/// hardcoded `+3n` — which happens to be right for secp256k1 at w=3 and is wrong
/// for P-384.
///
/// Stack in: [_k]. Stack out: [_result]. Returns false when no geometry exists.
fn emit_comb_mul_gen(
    emit: &mut dyn FnMut(StackOp),
    w: usize,
    opts: Option<&EcCodegenOptions>,
) -> bool {
    let curve = &*SECP256K1_COMB_CURVE;
    let params = match comb_geometry(w, curve) {
        Some(p) => p,
        None => return false,
    };
    let d = params.d;
    let table = comb_table(w, d, curve);
    let safe = comb_safe_rounds(&params, curve);
    let entries = (1usize << w) - 1;

    let mut t = ECTracker::with_opts(&["_k"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &FIELD_P);
    t.pool_constant(POOL_GROUP_N, &CURVE_N);

    // k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so
    // what makes the interval argument apply at all; see `emit_scalar_reduce`.
    t.to_top("_k");
    emit_scalar_reduce(&mut t, "_k", "_kr");
    t.rename("_k");
    let offset = params.offset_multiple.to_u32().expect("comb offset fits u32");
    for i in 0..offset {
        let off = format!("_off{}", i);
        t.push_const(POOL_GROUP_N, &CURVE_N, &off);
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
        jacobian_double(&mut t);
        comb_emit_select(&mut t, i, w, d);

        // `jacobian_add_affine_body` documents its layout as
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
                build_jacobian_add_affine_inline(add_emit, &t);
            } else {
                build_jacobian_add_or_double_inline(add_emit, &t);
            }
        });
        (t.e)(StackOp::If { then_ops: add_ops, else_ops: vec![] });

        // The addend was selected fresh for this round; the add only copied it.
        t.to_top("ay");
        t.drop();
        t.to_top("ax");
        t.drop();
    }

    jacobian_to_affine(&mut t, "_rx", "_ry");

    for j in (1..=entries).rev() {
        t.to_top(&format!("_Ty{}", j));
        t.drop();
        t.to_top(&format!("_Tx{}", j));
        t.drop();
    }
    t.to_top("_k");
    t.drop();

    compose_point(&mut t, "_rx", "_ry", "_result");
    t.release_constant(POOL_GROUP_N);
    t.release_constant(POOL_FIELD_P);
    true
}

/// Emit the cheapest comb over the candidate window widths.
///
/// Each candidate is rendered in full and scored with the same byte-cost model
/// the emitter is measured by, and the smallest wins — the window width is not
/// hardcoded. w=1 is the binary ladder and is excluded; beyond w=4 the `2^w`
/// selection logic outgrows the saving.
///
/// `None` when no candidate could be built, so the caller falls back to the
/// ladder rather than emitting nothing.
fn emit_comb_best(opts: Option<&EcCodegenOptions>) -> Option<Vec<StackOp>> {
    let mut best: Option<Vec<StackOp>> = None;
    for w in [2usize, 3, 4] {
        let mut ops: Vec<StackOp> = Vec::new();
        let built = {
            let mut sink = |op: StackOp| ops.push(op);
            emit_comb_mul_gen(&mut sink, w, opts)
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

/// ecMulGen: scalar multiplication G * k.
/// Stack in: [scalar]
/// Stack out: [result_point]
pub fn emit_ec_mul_gen(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    // G is a compile-time constant, so this is the one secp256k1 call site where
    // a fixed-base comb applies. `emit_ec_mul` cannot use it: its base arrives at
    // run time.
    if opts.map(|o| o.fixed_base_comb).unwrap_or(false) {
        if let Some(ops) = emit_comb_best(opts) {
            for op in ops {
                emit(op);
            }
            return;
        }
    }

    // Push generator point as 64-byte blob, then delegate to ecMul
    let mut g_point = Vec::with_capacity(64);
    g_point.extend_from_slice(&GEN_X_BYTES);
    g_point.extend_from_slice(&GEN_Y_BYTES);
    emit(StackOp::Push(PushValue::Bytes(g_point)));
    emit(StackOp::Swap); // [point, scalar]
    emit_ec_mul(emit, opts);
}

/// ecNegate: negate a point (x, p - y).
/// Stack in: [point]
/// Stack out: [negated_point]
pub fn emit_ec_negate(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &FIELD_P);
    decompose_point(&mut t, "_pt", "_nx", "_ny");
    push_field_p(&mut t, "_fp");
    field_sub(&mut t, "_fp", "_ny", "_neg_y");
    compose_point(&mut t, "_nx", "_neg_y", "_result");
    t.release_constant(POOL_FIELD_P);
}

/// ecOnCurve: check if point is on secp256k1 (y^2 = x^3 + 7 mod p).
/// Stack in: [point]
/// Stack out: [boolean]
pub fn emit_ec_on_curve(emit: &mut dyn FnMut(StackOp), opts: Option<&EcCodegenOptions>) {
    let mut t = ECTracker::with_opts(&["_pt"], emit, opts, None);
    t.pool_constant(POOL_FIELD_P, &FIELD_P);
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

    // on-curve = canonical AND curve-equation
    t.to_top("_canon");
    t.to_top("_curve_eq");
    t.raw_block(&["_canon", "_curve_eq"], Some("_result"), |e| {
        e(StackOp::Opcode("OP_BOOLAND".into()));
    });
    t.release_constant(POOL_FIELD_P);
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

