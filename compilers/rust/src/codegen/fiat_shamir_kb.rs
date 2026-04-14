//! Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear -- codegen for Bitcoin Script.
//!
//! Port of compilers/go/codegen/fiat_shamir_kb.go.
//!
//! Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
//!   - State width: 16 KoalaBear field elements
//!   - Rate: 8 elements (positions 0-7)
//!   - Capacity: 8 elements (positions 8-15)
//!
//! The sponge position is tracked at codegen time (in Rust), not at runtime (in Bitcoin Script).
//! Because the verifier's transcript structure is fully deterministic, we always know exactly
//! when to permute without runtime conditionals.
//!
//! Many of the emit_* and state-name helpers here are port-for-port mirrors of the Go
//! reference and are not yet wired into the Rust compiler's public codegen entry points;
//! they are kept intentionally available for the upcoming Groth16 / SP1 verifier port.

#![allow(dead_code)]

use super::koalabear::KBTracker;
use super::poseidon2_koalabear::{p2kb_permute, p2kb_state_name, p2kb_state_names};
use super::stack::{PushValue, StackOp};

// ===========================================================================
// Constants
// ===========================================================================

/// Full Poseidon2 state width (rate + capacity).
const FS_SPONGE_WIDTH: usize = 16;

/// Number of rate elements in the duplex sponge.
const FS_SPONGE_RATE: usize = 8;

// ===========================================================================
// State naming helpers
// ===========================================================================

/// Returns the canonical name for sponge state element i.
fn fs_sponge_state_name(i: usize) -> String {
    format!("fs{}", i)
}

// ===========================================================================
// FiatShamirState -- codegen-time duplex sponge state machine
// ===========================================================================

/// FiatShamirState tracks the duplex sponge position at codegen time, matching
/// Plonky3's DuplexChallenger semantics. The 16-element KoalaBear state lives
/// on the Bitcoin Script stack as fs0 (deepest) through fs15 (top).
///
/// Two independent positions are tracked:
///   - absorb_pos: where the next observation will be written (0..RATE-1)
///   - squeeze_pos: where the next squeeze will read from (0..RATE-1)
///   - output_valid: whether the current state has been permuted and is safe
///     to squeeze from (invalidated by any observation)
pub struct FiatShamirState {
    absorb_pos: usize,
    squeeze_pos: usize,
    output_valid: bool,
}

impl FiatShamirState {
    /// Creates a new sponge state. The initial state has no valid output
    /// (first squeeze will trigger a permutation).
    pub fn new() -> Self {
        FiatShamirState {
            absorb_pos: 0,
            squeeze_pos: 0,
            output_valid: false,
        }
    }

    /// Returns the current absorption position (for testing).
    pub fn absorb_pos(&self) -> usize {
        self.absorb_pos
    }

    /// Returns the current squeeze position (for testing).
    pub fn squeeze_pos(&self) -> usize {
        self.squeeze_pos
    }

    /// Returns whether the squeeze output cache is valid (for testing).
    pub fn output_valid(&self) -> bool {
        self.output_valid
    }
}

impl Default for FiatShamirState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// EmitInit -- push the initial all-zero sponge state
// ===========================================================================

/// emit_init pushes 16 zero-valued KoalaBear field elements onto the stack as
/// the initial sponge state. After this call the stack contains:
///
///   [..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
pub(crate) fn emit_init(fs: &mut FiatShamirState, t: &mut KBTracker) {
    for i in 0..FS_SPONGE_WIDTH {
        t.push_int(&fs_sponge_state_name(i), 0);
    }
    fs.absorb_pos = 0;
    fs.squeeze_pos = 0;
    fs.output_valid = false;
}

// ===========================================================================
// emit_permute -- rename sponge state, run Poseidon2, rename back
// ===========================================================================

/// emit_permute emits a full Poseidon2 permutation on the 16-element sponge state.
/// The sponge elements fs0..fs15 are renamed to _p2s0.._p2s15, the permutation
/// is applied, and the results are renamed back to fs0..fs15.
pub(crate) fn emit_permute(t: &mut KBTracker) {
    // Rename fs0..fs15 -> _p2s0.._p2s15 and reorder for Poseidon2.
    // Poseidon2 expects _p2s0 deepest, _p2s15 on top.
    for i in 0..FS_SPONGE_WIDTH {
        t.to_top(&fs_sponge_state_name(i));
        t.rename(&p2kb_state_name(i));
    }

    // Cache the KoalaBear prime on the alt-stack for the duration of the permutation.
    t.push_prime_cache();

    // Run the permutation.
    let mut names = p2kb_state_names();
    p2kb_permute(t, &mut names);

    t.pop_prime_cache();

    // Reorder post-permutation elements and rename back to fs0..fs15.
    for i in 0..FS_SPONGE_WIDTH {
        t.to_top(&p2kb_state_name(i));
        t.rename(&fs_sponge_state_name(i));
    }
}

// ===========================================================================
// EmitObserve -- absorb one field element into the sponge
// ===========================================================================

/// emit_observe absorbs one KoalaBear field element from the top of the stack
/// into the sponge state. The element replaces the current rate slot and the
/// absorption position advances. When the rate is filled (absorb_pos reaches
/// FS_SPONGE_RATE), a Poseidon2 permutation is emitted, the position resets,
/// and the squeeze output becomes valid.
///
/// Any observation invalidates cached squeeze outputs.
///
/// Stack in:  [..., fs0, ..., fs15, element]
/// Stack out: [..., fs0', ..., fs15']   (element consumed)
pub(crate) fn emit_observe(fs: &mut FiatShamirState, t: &mut KBTracker) {
    let target_name = fs_sponge_state_name(fs.absorb_pos);

    // The element to absorb is on top of the stack. Rename it to avoid collision.
    t.rename("_fs_absorb_elem");

    // Bring the target sponge slot to the top and drop it.
    t.to_top(&target_name);
    t.drop();

    // Move the absorbed element to the top and rename it to the sponge slot.
    t.to_top("_fs_absorb_elem");
    t.rename(&target_name);

    // Invalidate cached squeeze outputs.
    fs.output_valid = false;

    fs.absorb_pos += 1;
    if fs.absorb_pos == FS_SPONGE_RATE {
        // Rate full -- permute.
        emit_permute(t);
        fs.absorb_pos = 0;
        fs.squeeze_pos = 0;
        fs.output_valid = true;
    }
}

// ===========================================================================
// EmitSqueeze -- sample one field element from the sponge
// ===========================================================================

/// emit_squeeze samples one KoalaBear field element from the sponge, matching
/// Plonky3's DuplexChallenger behavior:
///
///  1. If the output is not valid or all rate elements have been consumed, a
///     permutation is emitted to produce fresh output.
///  2. The element at the current squeeze position is copied to the top of
///     the stack as "_fs_squeezed".
///  3. The squeeze position advances.
///
/// Stack in:  [..., fs0, ..., fs15]
/// Stack out: [..., fs0', ..., fs15', sampled]
pub(crate) fn emit_squeeze(fs: &mut FiatShamirState, t: &mut KBTracker) {
    if !fs.output_valid || fs.squeeze_pos >= FS_SPONGE_RATE {
        // No valid output available -- permute to produce fresh output.
        emit_permute(t);
        fs.absorb_pos = 0;
        fs.squeeze_pos = 0;
        fs.output_valid = true;
    }

    // Copy the current rate element to the top.
    let source_name = fs_sponge_state_name(fs.squeeze_pos);
    t.copy_to_top(&source_name, "_fs_squeezed");

    fs.squeeze_pos += 1;
}

// ===========================================================================
// EmitSqueezeExt4 -- sample a quartic extension element (4 field elements)
// ===========================================================================

/// emit_squeeze_ext4 samples 4 consecutive KoalaBear field elements from the
/// sponge, forming a quartic extension field element.
///
/// Stack in:  [..., fs0, ..., fs15]
/// Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
pub(crate) fn emit_squeeze_ext4(fs: &mut FiatShamirState, t: &mut KBTracker) {
    for i in 0..4 {
        emit_squeeze(fs, t);
        t.rename(&format!("_fs_ext4_{}", i));
    }
}

// ===========================================================================
// EmitSampleBits -- squeeze and extract low n bits
// ===========================================================================

/// emit_sample_bits squeezes one field element and extracts its low n bits.
/// The result is an integer in [0, 2^n).
///
/// Stack in:  [..., fs0, ..., fs15]
/// Stack out: [..., fs0', ..., fs15', bits]
pub(crate) fn emit_sample_bits(fs: &mut FiatShamirState, t: &mut KBTracker, n: usize) {
    assert!(
        n >= 1 && n <= 20,
        "emit_sample_bits: n must be in [1, 20], got {} (n>20 has non-negligible bias)",
        n
    );
    emit_squeeze(fs, t);
    // _fs_squeezed is on top. Mask to low n bits: val % (2^n).
    let mask: i64 = 1i64 << n;
    t.raw_block(&["_fs_squeezed"], Some("_fs_bits"), |e| {
        e(StackOp::Push(PushValue::Int(mask as i128)));
        e(StackOp::Opcode("OP_MOD".into()));
    });
}

// ===========================================================================
// EmitCheckWitness -- verify proof-of-work on sponge state
// ===========================================================================

/// emit_check_witness absorbs a witness element from the top of the stack,
/// squeezes a challenge, and verifies that the low `bits` bits of the
/// challenge are all zero (proof-of-work check).
///
/// Stack in:  [..., fs0, ..., fs15, witness]
/// Stack out: [..., fs0', ..., fs15']   (witness consumed, assert on failure)
pub(crate) fn emit_check_witness(fs: &mut FiatShamirState, t: &mut KBTracker, bits: usize) {
    assert!(
        bits >= 1 && bits <= 30,
        "emit_check_witness: bits must be in [1, 30] (KoalaBear field is 31-bit), got {}",
        bits
    );

    // Absorb the witness.
    emit_observe(fs, t);

    // Squeeze a challenge element.
    emit_squeeze(fs, t);

    // Extract low `bits` bits and assert they are zero.
    let mask: i64 = 1i64 << bits;
    t.raw_block(&["_fs_squeezed"], Some("_fs_pow_check"), |e| {
        e(StackOp::Push(PushValue::Int(mask as i128)));
        e(StackOp::Opcode("OP_MOD".into()));
    });
    // Assert _fs_pow_check == 0: push 0, check equal, assert.
    t.push_int("_fs_pow_zero", 0);
    t.raw_block(&["_fs_pow_check", "_fs_pow_zero"], None, |e| {
        e(StackOp::Opcode("OP_NUMEQUAL".into()));
        e(StackOp::Opcode("OP_VERIFY".into()));
    });
}
