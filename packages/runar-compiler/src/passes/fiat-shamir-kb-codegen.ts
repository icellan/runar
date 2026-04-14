/**
 * Fiat-Shamir duplex sponge (DuplexChallenger) over KoalaBear — Bitcoin Script codegen.
 *
 * Ports compilers/go/codegen/fiat_shamir_kb.go to TypeScript.
 *
 * Implements the Fiat-Shamir challenge derivation used by SP1's StackedBasefold
 * verifier. The sponge uses Poseidon2 as the permutation primitive.
 *
 * Parameters (SP1 v6, DuplexChallenger<KoalaBear, KoalaPerm, 16, 8>):
 *   - State width: 16 KoalaBear field elements
 *   - Rate: 8 elements (positions 0–7)
 *   - Capacity: 8 elements (positions 8–15)
 *
 * Key design property: the sponge position is tracked at codegen time (in
 * TypeScript), not at runtime (in Bitcoin Script). Because the verifier's
 * transcript structure is fully deterministic, we always know exactly when to
 * permute without runtime conditionals.
 *
 * Matches Plonky3 DuplexChallenger behavior:
 *   - Observations write directly into the sponge state and invalidate cached
 *     squeeze outputs. When the rate is filled, the state is permuted.
 *   - Squeezing reads consecutive elements from the permuted state. A single
 *     permutation provides up to RATE (8) squeeze outputs.
 *   - Any observation after squeezing invalidates the cached outputs.
 *
 * The sponge state lives on the Bitcoin Script stack as fs0 (deepest) through
 * fs15 (top). This module is NOT registered as a contract-level builtin —
 * it is used programmatically by verifier codegen.
 */

import { KBTracker } from './koalabear-codegen.js';
import { p2KBPermuteOnTracker } from './poseidon2-koalabear-codegen.js';

// ===========================================================================
// Constants
// ===========================================================================

/** Full Poseidon2 state width (rate + capacity). */
const FS_SPONGE_WIDTH = 16;

/** Number of rate elements in the duplex sponge. */
const FS_SPONGE_RATE = 8;

// ===========================================================================
// State naming helpers
// ===========================================================================

function fsSpongeStateName(i: number): string { return `fs${i}`; }

// ===========================================================================
// FiatShamirState — codegen-time duplex sponge state machine
// ===========================================================================

/**
 * FiatShamirState tracks the duplex sponge position at codegen time,
 * matching Plonky3's DuplexChallenger semantics.
 *
 * The 16-element KoalaBear state lives on the Bitcoin Script stack as
 * fs0 (deepest) through fs15 (top).
 *
 * Two independent positions are tracked:
 *   - absorbPos: where the next observation will be written (0..RATE-1)
 *   - squeezePos: where the next squeeze will read from (0..RATE-1)
 *   - outputValid: whether the current state has been permuted and is safe
 *     to squeeze from (invalidated by any observation)
 */
export class FiatShamirState {
  private absorbPos: number = 0;
  private squeezePos: number = 0;
  private outputValid: boolean = false;

  /** Returns the current absorption position (for testing). */
  getAbsorbPos(): number { return this.absorbPos; }

  /** Returns the current squeeze position (for testing). */
  getSqueezePos(): number { return this.squeezePos; }

  /** Returns whether the squeeze output cache is valid (for testing). */
  isOutputValid(): boolean { return this.outputValid; }

  // ===========================================================================
  // EmitInit — push the initial all-zero sponge state
  // ===========================================================================

  /**
   * EmitInit pushes 16 zero-valued KoalaBear field elements onto the stack as
   * the initial sponge state. After this call the stack contains:
   *
   *   [..., fs0=0, fs1=0, ..., fs15=0]  (fs15 on top)
   */
  emitInit(t: KBTracker): void {
    for (let i = 0; i < FS_SPONGE_WIDTH; i++) {
      t.pushInt(fsSpongeStateName(i), 0n);
    }
    this.absorbPos = 0;
    this.squeezePos = 0;
    this.outputValid = false;
  }

  // ===========================================================================
  // emitPermute — rename sponge state, run Poseidon2, rename back
  // ===========================================================================

  /**
   * emitPermute emits a full Poseidon2 permutation on the 16-element sponge
   * state. The sponge elements fs0..fs15 are renamed to the Poseidon2
   * canonical names _p2s0.._p2s15, the permutation is applied, and the
   * results are renamed back to fs0..fs15.
   */
  private emitPermute(t: KBTracker): void {
    // Rename fs0..fs15 → _p2s0.._p2s15 and reorder for Poseidon2.
    // Poseidon2 expects _p2s0 deepest, _p2s15 on top.
    for (let i = 0; i < FS_SPONGE_WIDTH; i++) {
      t.toTop(fsSpongeStateName(i));
      t.rename(`_p2s${i}`);
    }

    // Cache the KoalaBear prime on the alt-stack for the duration of the
    // permutation. Without this, every field operation pushes a fresh 5-byte
    // prime literal, adding ~50 KB of unnecessary script per permutation.
    t.pushPrimeCache();

    // Run the permutation using the shared internal helper.
    p2KBPermuteOnTracker(t);

    t.popPrimeCache();

    // Reorder post-permutation elements and rename back to fs0..fs15.
    for (let i = 0; i < FS_SPONGE_WIDTH; i++) {
      t.toTop(`_p2s${i}`);
      t.rename(fsSpongeStateName(i));
    }
  }

  // ===========================================================================
  // EmitObserve — absorb one field element into the sponge
  // ===========================================================================

  /**
   * EmitObserve absorbs one KoalaBear field element from the top of the stack
   * into the sponge state. The element replaces the current rate slot and the
   * absorption position advances. When the rate is filled (absorbPos reaches
   * FS_SPONGE_RATE), a Poseidon2 permutation is emitted, the position resets,
   * and the squeeze output becomes valid.
   *
   * Any observation invalidates cached squeeze outputs, matching
   * DuplexChallenger behavior where observation clears the output buffer.
   *
   * Stack in:  [..., fs0, ..., fs15, element]
   * Stack out: [..., fs0', ..., fs15']   (element consumed)
   */
  emitObserve(t: KBTracker): void {
    const targetName = fsSpongeStateName(this.absorbPos);

    // The element to absorb is on top of the stack. Rename it to a temp name
    // to avoid collision with the target sponge slot.
    t.rename('_fs_absorb_elem');

    // Bring the target sponge slot to the top and drop it.
    t.toTop(targetName);
    t.drop();

    // Move the absorbed element to the top and rename it to the sponge slot.
    t.toTop('_fs_absorb_elem');
    t.rename(targetName);

    // Invalidate cached squeeze outputs — any observation means the state has
    // been modified and cannot be squeezed from without a fresh permutation.
    this.outputValid = false;

    this.absorbPos++;
    if (this.absorbPos === FS_SPONGE_RATE) {
      // Rate full — permute. After permutation, squeeze output is valid.
      this.emitPermute(t);
      this.absorbPos = 0;
      this.squeezePos = 0;
      this.outputValid = true;
    }
  }

  // ===========================================================================
  // EmitSqueeze — sample one field element from the sponge
  // ===========================================================================

  /**
   * EmitSqueeze samples one KoalaBear field element from the sponge,
   * matching Plonky3's DuplexChallenger behavior:
   *
   * 1. If the output is not valid (observations have been made since last
   *    permutation) or all rate elements have been consumed (squeezePos >= RATE),
   *    a permutation is emitted to produce fresh output.
   * 2. The element at the current squeeze position is copied to the top of
   *    the stack as "_fs_squeezed".
   * 3. The squeeze position advances. Up to RATE (8) consecutive squeezes
   *    can be served from a single permutation.
   *
   * Stack in:  [..., fs0, ..., fs15]
   * Stack out: [..., fs0', ..., fs15', sampled]
   */
  emitSqueeze(t: KBTracker): void {
    if (!this.outputValid || this.squeezePos >= FS_SPONGE_RATE) {
      // No valid output available — permute to produce fresh output.
      this.emitPermute(t);
      this.absorbPos = 0;
      this.squeezePos = 0;
      this.outputValid = true;
    }

    // Copy the current rate element to the top.
    const sourceName = fsSpongeStateName(this.squeezePos);
    t.copyToTop(sourceName, '_fs_squeezed');

    this.squeezePos++;
  }

  // ===========================================================================
  // EmitSqueezeExt4 — sample a quartic extension element (4 field elements)
  // ===========================================================================

  /**
   * EmitSqueezeExt4 samples 4 consecutive KoalaBear field elements from the
   * sponge, forming a quartic extension field element. This is equivalent to 4
   * sequential squeezes. With DuplexChallenger semantics, at most one
   * permutation is needed (since 4 < RATE = 8).
   *
   * Stack in:  [..., fs0, ..., fs15]
   * Stack out: [..., fs0', ..., fs15', e0, e1, e2, e3]
   */
  emitSqueezeExt4(t: KBTracker): void {
    for (let i = 0; i < 4; i++) {
      this.emitSqueeze(t);
      // Rename from _fs_squeezed to a numbered output name.
      t.rename(`_fs_ext4_${i}`);
    }
  }

  // ===========================================================================
  // EmitSampleBits — squeeze and extract low n bits
  // ===========================================================================

  /**
   * EmitSampleBits squeezes one field element and extracts its low n bits.
   * The result is an integer in [0, 2^n).
   *
   * n must be in [1, 20]. For n > 20, statistical bias from val % 2^n is
   * non-negligible relative to KoalaBear's prime (p = 2^31 - 2^24 + 1).
   *
   * Stack in:  [..., fs0, ..., fs15]
   * Stack out: [..., fs0', ..., fs15', bits]
   */
  emitSampleBits(t: KBTracker, n: number): void {
    if (n < 1 || n > 20) {
      throw new Error(
        `FiatShamirState.emitSampleBits: n must be in [1, 20], got ${n} ` +
        `(n>20 has non-negligible bias over KoalaBear prime)`,
      );
    }
    this.emitSqueeze(t);
    // _fs_squeezed is on top. Mask to low n bits: val % (2^n).
    const mask = 1n << BigInt(n);
    t.rawBlock(['_fs_squeezed'], '_fs_bits', (e) => {
      e({ op: 'push', value: mask });
      e({ op: 'opcode', code: 'OP_MOD' });
    });
  }

  // ===========================================================================
  // EmitCheckWitness — verify proof-of-work on sponge state
  // ===========================================================================

  /**
   * EmitCheckWitness absorbs a witness element from the top of the stack,
   * squeezes a challenge, and verifies that the low `bits` bits of the
   * challenge are all zero (proof-of-work check).
   *
   * bits must be in [1, 30]. Unlike EmitSampleBits, bias doesn't affect PoW
   * correctness — it only changes the probability of finding a valid witness.
   *
   * Stack in:  [..., fs0, ..., fs15, witness]
   * Stack out: [..., fs0', ..., fs15']   (witness consumed, script fails if PoW invalid)
   */
  emitCheckWitness(t: KBTracker, bits: number): void {
    if (bits < 1 || bits > 30) {
      throw new Error(
        `FiatShamirState.emitCheckWitness: bits must be in [1, 30] ` +
        `(KoalaBear field is 31-bit), got ${bits}`,
      );
    }

    // Absorb the witness.
    this.emitObserve(t);

    // Squeeze a challenge element.
    this.emitSqueeze(t);

    // Extract low `bits` bits and assert they are zero.
    const mask = 1n << BigInt(bits);
    t.rawBlock(['_fs_squeezed'], '_fs_pow_check', (e) => {
      e({ op: 'push', value: mask });
      e({ op: 'opcode', code: 'OP_MOD' });
    });

    // Assert _fs_pow_check == 0
    t.pushInt('_fs_pow_zero', 0n);
    t.rawBlock(['_fs_pow_check', '_fs_pow_zero'], '', (e) => {
      e({ op: 'opcode', code: 'OP_NUMEQUAL' });
      e({ op: 'opcode', code: 'OP_VERIFY' });
    });
  }
}
