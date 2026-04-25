// Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear — codegen for Bitcoin Script.
//
// Implements the Fiat-Shamir challenge derivation used by SP1's StackedBasefold
// verifier. The sponge uses Poseidon2 as the permutation primitive.
//
// Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
//   - State width: 16 KoalaBear field elements
//   - Rate: 8 elements (positions 0-7)
//   - Capacity: 8 elements (positions 8-15)
//
// Key design property: the sponge position is tracked at codegen time (in Go),
// not at runtime (in Bitcoin Script). Because the verifier's transcript structure
// is fully deterministic, we always know exactly when to permute without runtime
// conditionals.
//
// Matches Plonky3 DuplexChallenger behavior:
//   - Observations write directly into the sponge state and invalidate cached
//     squeeze outputs. When the rate is filled, the state is permuted.
//   - Squeezing reads consecutive elements from the permuted state. A single
//     permutation provides up to RATE (8) squeeze outputs. Only when all cached
//     outputs are consumed does the next squeeze trigger a fresh permutation.
//   - Any observation after squeezing invalidates the cached outputs.
//
// This module provides codegen-time helpers used by the Basefold verifier's
// codegen. It is NOT registered as a contract-level builtin.
package codegen

import "fmt"

// ===========================================================================
// Constants
// ===========================================================================

// fsSpongeWidth is the full Poseidon2 state width (rate + capacity).
const fsSpongeWidth = 16

// fsSpongeRate is the number of rate elements in the duplex sponge.
const fsSpongeRate = 8

// ===========================================================================
// State naming helpers
// ===========================================================================

// fsSpongeStateName returns the canonical name for sponge state element i.
func fsSpongeStateName(i int) string {
	return fmt.Sprintf("fs%d", i)
}

// ===========================================================================
// FiatShamirState — codegen-time duplex sponge state machine
// ===========================================================================

// FiatShamirState tracks the duplex sponge position at codegen time, matching
// Plonky3's DuplexChallenger semantics. The 16-element KoalaBear state lives
// on the Bitcoin Script stack as fs0 (deepest) through fs15 (top).
//
// Two independent positions are tracked:
//   - absorbPos: where the next observation will be written (0..RATE-1)
//   - squeezePos: where the next squeeze will read from (0..RATE-1)
//   - outputValid: whether the current state has been permuted and is safe
//     to squeeze from (invalidated by any observation)
type FiatShamirState struct {
	absorbPos   int  // absorption position in rate (0 .. fsSpongeRate-1)
	squeezePos  int  // squeeze position in rate (0 .. fsSpongeRate-1)
	outputValid bool // true when permuted output is available for squeezing
}

// NewFiatShamirState creates a new sponge state. The initial state has no
// valid output (first squeeze will trigger a permutation).
func NewFiatShamirState() *FiatShamirState {
	return &FiatShamirState{absorbPos: 0, squeezePos: 0, outputValid: false}
}

// AbsorbPos returns the current absorption position (for testing).
func (fs *FiatShamirState) AbsorbPos() int {
	return fs.absorbPos
}

// SqueezePos returns the current squeeze position (for testing).
func (fs *FiatShamirState) SqueezePos() int {
	return fs.squeezePos
}

// OutputValid returns whether the squeeze output cache is valid (for testing).
func (fs *FiatShamirState) OutputValid() bool {
	return fs.outputValid
}

// ===========================================================================
// EmitInit — push the initial all-zero sponge state
// ===========================================================================

// EmitInit pushes 16 zero-valued KoalaBear field elements onto the stack as
// the initial sponge state. After this call the stack contains:
//
//	[..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
func (fs *FiatShamirState) EmitInit(t *KBTracker) {
	for i := 0; i < fsSpongeWidth; i++ {
		t.pushInt(fsSpongeStateName(i), 0)
	}
	fs.absorbPos = 0
	fs.squeezePos = 0
	fs.outputValid = false
}

// ===========================================================================
// emitPermute — rename sponge state, run Poseidon2, rename back
// ===========================================================================

// emitPermute emits a full Poseidon2 permutation on the 16-element sponge
// state. The sponge elements fs0..fs15 are renamed to the Poseidon2 canonical
// names _p2s0.._p2s15, the permutation is applied, and the results are
// renamed back to fs0..fs15.
func (fs *FiatShamirState) emitPermute(t *KBTracker) {
	// Rename fs0..fs15 → _p2s0.._p2s15 and reorder for Poseidon2.
	// Poseidon2 expects _p2s0 deepest, _p2s15 on top.
	for i := 0; i < fsSpongeWidth; i++ {
		t.toTop(fsSpongeStateName(i))
		t.rename(poseidon2KBStateName(i))
	}

	// Cache the KoalaBear prime on the alt-stack for the duration of the
	// permutation. Without this, every field operation pushes a fresh 5-byte
	// prime literal, adding ~50 KB of unnecessary script per permutation.
	t.PushPrimeCache()

	// Run the permutation.
	names := poseidon2KBStateNames()
	poseidon2KBPermute(t, names)

	t.PopPrimeCache()

	// Reorder post-permutation elements and rename back to fs0..fs15.
	for i := 0; i < fsSpongeWidth; i++ {
		t.toTop(poseidon2KBStateName(i))
		t.rename(fsSpongeStateName(i))
	}
}

// ===========================================================================
// EmitObserve — absorb one field element into the sponge
// ===========================================================================

// EmitObserve absorbs one KoalaBear field element from the top of the stack
// into the sponge state. The element replaces the current rate slot and the
// absorption position advances. When the rate is filled (absorbPos reaches
// fsSpongeRate), a Poseidon2 permutation is emitted, the position resets,
// and the squeeze output becomes valid.
//
// Any observation invalidates cached squeeze outputs, matching DuplexChallenger
// behavior where observation clears the output buffer.
//
// Stack in:  [..., fs0, ..., fs15, element]
// Stack out: [..., fs0', ..., fs15']   (element consumed)
func (fs *FiatShamirState) EmitObserve(t *KBTracker) {
	targetName := fsSpongeStateName(fs.absorbPos)

	// The element to absorb is on top of the stack. Rename it to a temp name
	// to avoid collision with the target sponge slot.
	t.rename("_fs_absorb_elem")

	// Bring the target sponge slot to the top and drop it.
	t.toTop(targetName)
	t.drop()

	// Move the absorbed element to the top and rename it to the sponge slot.
	t.toTop("_fs_absorb_elem")
	t.rename(targetName)

	// Invalidate cached squeeze outputs — any observation means the state has
	// been modified and cannot be squeezed from without a fresh permutation.
	fs.outputValid = false

	fs.absorbPos++
	if fs.absorbPos == fsSpongeRate {
		// Rate full — permute. After permutation, squeeze output is valid.
		fs.emitPermute(t)
		fs.absorbPos = 0
		fs.squeezePos = 0
		fs.outputValid = true
	}
}

// ===========================================================================
// EmitSqueeze — sample one field element from the sponge
// ===========================================================================

// EmitSqueeze samples one KoalaBear field element from the sponge, matching
// Plonky3's DuplexChallenger behavior:
//
//  1. If the output is not valid (observations have been made since last
//     permutation) or all rate elements have been consumed (squeezePos >= RATE),
//     a permutation is emitted to produce fresh output.
//  2. The element at the current squeeze position is copied to the top of
//     the stack as "_fs_squeezed". Plonky3's `DuplexChallenger::sample`
//     (challenger/src/duplex_challenger.rs lines 196-216, validated by the
//     port at packages/runar-go/sp1fri/challenger.go:103-112) pops from the
//     **back** of the rate window: outputBuffer[len-1], outputBuffer[len-2],
//     ... So the i-th sample after a permutation is rate element
//     `(rate-1) - i`, not rate element `i`.
//  3. The squeeze position advances. Up to RATE (8) consecutive squeezes
//     can be served from a single permutation.
//
// Stack in:  [..., fs0, ..., fs15]
// Stack out: [..., fs0', ..., fs15', sampled]
func (fs *FiatShamirState) EmitSqueeze(t *KBTracker) {
	if !fs.outputValid || fs.squeezePos >= fsSpongeRate {
		// No valid output available — permute to produce fresh output.
		fs.emitPermute(t)
		fs.absorbPos = 0
		fs.squeezePos = 0
		fs.outputValid = true
	}

	// Copy the current rate element to the top. Sample order matches
	// Plonky3 DuplexChallenger.Sample(): pop from the back of the rate window.
	sourceName := fsSpongeStateName(fsSpongeRate - 1 - fs.squeezePos)
	t.copyToTop(sourceName, "_fs_squeezed")

	fs.squeezePos++
}

// ===========================================================================
// EmitSqueezeExt4 — sample a quartic extension element (4 field elements)
// ===========================================================================

// EmitSqueezeExt4 samples 4 consecutive KoalaBear field elements from the
// sponge, forming a quartic extension field element. This is equivalent to 4
// sequential squeezes. With DuplexChallenger semantics, at most one permutation
// is needed (since 4 < RATE = 8).
//
// Stack in:  [..., fs0, ..., fs15]
// Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
func (fs *FiatShamirState) EmitSqueezeExt4(t *KBTracker) {
	for i := 0; i < 4; i++ {
		fs.EmitSqueeze(t)
		// Rename from _fs_squeezed to a numbered output name.
		t.rename(fmt.Sprintf("_fs_ext4_%d", i))
	}
}

// ===========================================================================
// EmitSampleBits — squeeze and extract low n bits
// ===========================================================================

// EmitSampleBits squeezes one field element and extracts its low n bits.
// The result is an integer in [0, 2^n).
//
// Stack in:  [..., fs0, ..., fs15]
// Stack out: [..., fs0', ..., fs15', bits]
func (fs *FiatShamirState) EmitSampleBits(t *KBTracker, n int) {
	if n < 1 || n > 20 {
		// Capped at 20 as a conservative limit for statistical bias.
		// The squeezed value is uniform in [0, p-1] where p = 2^31 - 2^24 + 1.
		// Since p mod 2^n = 1 for all n <= 24 (p = 2^31 - 2^24 + 1), the bias
		// from val % 2^n is negligible for n <= 24. However, we cap at 20 to
		// provide margin for applications requiring strong uniformity guarantees.
		// For n >= 25, p mod 2^n deviates significantly and bias becomes
		// problematic for challenge sampling.
		panic(fmt.Sprintf("EmitSampleBits: n must be in [1, 20], got %d (n>20 has non-negligible bias)", n))
	}
	fs.EmitSqueeze(t)
	// _fs_squeezed is on top. Mask to low n bits: val % (2^n).
	mask := int64(1) << uint(n)
	t.rawBlock([]string{"_fs_squeezed"}, "_fs_bits", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(mask)})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
}

// ===========================================================================
// EmitCheckWitness — verify proof-of-work on sponge state
// ===========================================================================

// EmitCheckWitness absorbs a witness element from the top of the stack,
// squeezes a challenge, and verifies that the low `bits` bits of the
// challenge are all zero (proof-of-work check).
//
// Stack in:  [..., fs0, ..., fs15, witness]
// Stack out: [..., fs0', ..., fs15']   (witness consumed, assert on failure)
func (fs *FiatShamirState) EmitCheckWitness(t *KBTracker, bits int) {
	if bits < 1 || bits > 30 {
		// Unlike EmitSampleBits (capped at 20), PoW checks allow up to 30 bits
		// because bias doesn't affect the validity of a zero-check — it only
		// changes the probability of finding a valid witness, which the prover
		// controls by trying more nonces.
		panic(fmt.Sprintf("EmitCheckWitness: bits must be in [1, 30] (KoalaBear field is 31-bit), got %d", bits))
	}

	// Absorb the witness.
	fs.EmitObserve(t)

	// Squeeze a challenge element.
	fs.EmitSqueeze(t)

	// Extract low `bits` bits and assert they are zero.
	mask := int64(1) << uint(bits)
	t.rawBlock([]string{"_fs_squeezed"}, "_fs_pow_check", func(e func(StackOp)) {
		e(StackOp{Op: "push", Value: bigIntPush(mask)})
		e(StackOp{Op: "opcode", Code: "OP_MOD"})
	})
	// Assert _fs_pow_check == 0: push 0, check equal, assert.
	t.pushInt("_fs_pow_zero", 0)
	t.rawBlock([]string{"_fs_pow_check", "_fs_pow_zero"}, "", func(e func(StackOp)) {
		e(StackOp{Op: "opcode", Code: "OP_NUMEQUAL"})
		e(StackOp{Op: "opcode", Code: "OP_VERIFY"})
	})
}
