/**
 * BN254 Fp field arithmetic → Bitcoin Script codegen.
 *
 * Generates StackOp[] sequences for modular arithmetic on 256-bit field
 * elements. Follows the same pattern as ec-codegen.ts and sha256-codegen.ts.
 *
 * ## BSV advantages for field arithmetic
 *
 * BSV has restored all original Bitcoin opcodes and removed script limits:
 * - **OP_MUL**: Native arbitrary-precision integer multiplication. This is
 *   the single biggest advantage — on BTC, 256-bit multiplication requires
 *   Karatsuba/schoolbook decomposition (~100x overhead).
 * - **OP_MOD**: Native modular reduction on arbitrary-precision integers.
 * - **OP_LSHIFT/OP_RSHIFT**: Bitwise shifts on byte arrays (logical, not arithmetic).
 * - **OP_AND/OP_OR/OP_XOR**: Bitwise ops on equal-length byte arrays.
 * - **No element size limit** (BSV removed the 520-byte limit).
 * - **No opcode count limit** (32 MB stack memory limit instead).
 *
 * ## Optimization strategy
 *
 * 1. **Altstack P caching**: The field prime P is pushed once and kept on
 *    the altstack. Each use: FROMALTSTACK DUP TOALTSTACK = 3 bytes to get
 *    a copy, vs 34 bytes to push the constant fresh each time.
 *
 * 2. **Lazy reduction**: Inputs to all operations are assumed to be already
 *    in [0, p). Products a*b ∈ [0, p²) are always non-negative, so OP_MOD
 *    always returns a non-negative result — no negative fixup needed.
 *    Sums a+b ∈ [0, 2p) — OP_MOD handles this correctly.
 *    Differences a-b ∈ (-p, p) — add p first to guarantee non-negative.
 *
 * 3. **Script number format**: BSV script numbers are arbitrary-precision
 *    integers in little-endian sign-magnitude. Field elements stay as
 *    script numbers throughout computation — no byte-array conversion needed.
 *
 * ## Cost per operation (with altstack P)
 *
 * | Operation | Opcodes | Bytes |
 * |-----------|---------|-------|
 * | fpMod     | 4       | 4     |
 * | fpAdd     | 5       | 5     |
 * | fpSub     | 8       | 8     |
 * | fpMul     | 5       | 5     |
 * | fpSqr     | 6       | 6     |
 * | fpNeg     | 5       | 5     |
 * | fpInv     | ~2000   | ~2 KB |
 */

import type { StackOp } from 'runar-ir-schema';
import { P, P_MINUS_2 } from './constants.js';

// ---------------------------------------------------------------------------
// Prime P management
// ---------------------------------------------------------------------------

/**
 * Initialize P for a codegen block. Now a no-op — P is pushed inline
 * by emitGetP each time it's needed, freeing the altstack for Fp6/Fp12
 * intermediate storage.
 */
export function emitInitP(_ops: StackOp[]): void {
  // no-op: P is pushed inline by emitGetP
}

/**
 * Push P onto the main stack.
 * Stack: [...] → [..., P]
 */
function emitGetP(ops: StackOp[]): void {
  ops.push({ op: 'push', value: P } as StackOp);
}

/**
 * Cleanup P after a codegen block. Now a no-op — P is not cached.
 */
export function emitCleanupP(_ops: StackOp[]): void {
  // no-op: P is pushed inline by emitGetP
}

// ---------------------------------------------------------------------------
// Core field operations (altstack P assumed present)
// ---------------------------------------------------------------------------

/**
 * Emit: a mod p (non-negative result guaranteed for non-negative a).
 * Stack: [..., a] → [..., a mod p]
 * Ops: 4 (getP + MOD)
 */
export function emitFpMod(ops: StackOp[]): void {
  emitGetP(ops); // 3 ops
  ops.push({ op: 'opcode', code: 'OP_MOD' } as StackOp); // 1 op
}

/**
 * Emit: (a + b) mod p
 * Stack: [..., a, b] → [..., (a+b) mod p]
 * Ops: 5 (ADD + getP + MOD)
 * Note: a,b ∈ [0,p) → a+b ∈ [0,2p) → always non-negative, MOD is correct.
 */
export function emitFpAdd(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_ADD' } as StackOp);
  emitFpMod(ops);
}

/**
 * Emit: (a - b) mod p
 * Stack: [..., a, b] → [..., (a-b) mod p]
 * Ops: 8 (getP + ADD + SUB + getP + MOD)
 * Strategy: compute (a + p - b) mod p. Since a,b ∈ [0,p), a+p-b ∈ (0, 2p).
 * Always non-negative, so MOD returns correct result.
 */
export function emitFpSub(ops: StackOp[]): void {
  // Stack: [a, b]
  // We want (a - b + p) mod p
  emitGetP(ops);                                            // [a, b, P]
  ops.push({ op: 'swap' } as StackOp);                     // [a, P, b]
  ops.push({ op: 'opcode', code: 'OP_SUB' } as StackOp);  // [a, P-b]
  ops.push({ op: 'opcode', code: 'OP_ADD' } as StackOp);  // [a+P-b]
  emitFpMod(ops);                                           // [(a+P-b) mod p]
}

/**
 * Emit: (a * b) mod p
 * Stack: [..., a, b] → [..., (a*b) mod p]
 * Ops: 5 (MUL + getP + MOD)
 * Note: a,b ∈ [0,p) → a*b ∈ [0,p²) → always non-negative, MOD is correct.
 */
export function emitFpMul(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_MUL' } as StackOp);
  emitFpMod(ops);
}

/**
 * Emit: (-a) mod p = (p - a) mod p
 * Stack: [..., a] → [..., p - a]
 * Ops: 5 (getP + SWAP + SUB + getP + MOD)
 * For a ∈ [0,p): p-a ∈ (0,p], already reduced (except a=0 → p, needs MOD).
 */
export function emitFpNeg(ops: StackOp[]): void {
  emitGetP(ops);
  ops.push({ op: 'swap' } as StackOp);
  ops.push({ op: 'opcode', code: 'OP_SUB' } as StackOp);
  // p - 0 = p needs reducing to 0; all other cases are in [1, p-1]
  emitFpMod(ops);
}

/**
 * Emit: a^2 mod p
 * Stack: [..., a] → [..., a^2 mod p]
 * Ops: 6 (DUP + MUL + getP + MOD)
 */
export function emitFpSqr(ops: StackOp[]): void {
  ops.push({ op: 'opcode', code: 'OP_DUP' } as StackOp);
  emitFpMul(ops);
}

/** Push a field element constant. */
export function emitPushFp(ops: StackOp[], value: bigint): void {
  ops.push({ op: 'push', value } as StackOp);
}

/** Push P (standalone, not from altstack). */
export function emitPushP(ops: StackOp[]): void {
  ops.push({ op: 'push', value: P } as StackOp);
}

// ---------------------------------------------------------------------------
// Modular inverse: a^{p-2} mod p (Fermat's little theorem)
// ---------------------------------------------------------------------------

/**
 * Emit: a^{-1} mod p via binary exponentiation of p-2.
 * Stack: [..., a] → [..., a^{-1} mod p]
 *
 * p-2 has 254 bits, ~127 set bits.
 * Cost: 254 squarings + ~127 multiplications.
 * Each sqr = 6 bytes, each mul = 5 bytes (with OVER for base).
 * Total: 254×6 + 127×(1+5) + overhead ≈ 2300 bytes (~2.3 KB).
 */
export function emitFpInv(ops: StackOp[]): void {
  const exp = P_MINUS_2;
  const bits: number[] = [];
  let v = exp;
  while (v > 0n) {
    bits.push(Number(v & 1n));
    v >>= 1n;
  }

  // Stack: [..., base]
  // Start: push result=1
  ops.push({ op: 'push', value: 1n } as StackOp); // [..., base, result=1]

  // Process MSB to LSB
  for (let i = bits.length - 1; i >= 0; i--) {
    // Square result
    ops.push({ op: 'opcode', code: 'OP_DUP' } as StackOp);
    emitFpMul(ops); // result = result² mod p

    if (bits[i] === 1) {
      // Multiply by base
      ops.push({ op: 'opcode', code: 'OP_OVER' } as StackOp);
      emitFpMul(ops); // result = result * base mod p
    }
  }

  // Drop base, keep result
  ops.push({ op: 'swap' } as StackOp);
  ops.push({ op: 'drop' } as StackOp);
}

// ---------------------------------------------------------------------------
// Feasibility metrics
// ---------------------------------------------------------------------------

/** Count bits set in a bigint. */
function popcount(n: bigint): number {
  let count = 0;
  let v = n;
  while (v > 0n) {
    if (v & 1n) count++;
    v >>= 1n;
  }
  return count;
}

/** Count total bits in a bigint. */
function bitLength(n: bigint): number {
  let count = 0;
  let v = n;
  while (v > 0n) {
    count++;
    v >>= 1n;
  }
  return count;
}

/**
 * Estimate byte sizes for field operations (with altstack P optimization).
 */
export function estimateOpSizes(): Record<string, { ops: number; bytes: number }> {
  // With altstack P: getP = 3 bytes (FROMALT DUP TOALT)
  const GET_P = 3;
  const MOD_COST = GET_P + 1; // getP + OP_MOD = 4 bytes

  const fpMod = MOD_COST;
  const fpAdd = 1 + MOD_COST;            // ADD + mod = 5
  const fpSub = GET_P + 1 + 1 + 1 + MOD_COST; // getP(3) + ROT(1) + SUB(1) + ADD(1) + mod(4) = 10
  const fpMul = 1 + MOD_COST;            // MUL + mod = 5
  const fpSqr = 1 + fpMul;               // DUP + fpMul = 6
  const fpNeg = GET_P + 1 + 1 + MOD_COST; // getP + SWAP + SUB + mod = 8

  const expBits = bitLength(P_MINUS_2);
  const expOnes = popcount(P_MINUS_2);
  // Per bit: 1 DUP + fpMul (sqr). Set bits: +1 OVER + fpMul.
  const fpInv = 1 + // initial push(1)
    expBits * (1 + fpMul) + // squarings: DUP + fpMul per bit
    expOnes * (1 + fpMul) + // multiplications: OVER + fpMul per set bit
    2; // SWAP + DROP at end

  return {
    fpMod: { ops: fpMod, bytes: fpMod },
    fpAdd: { ops: fpAdd, bytes: fpAdd },
    fpSub: { ops: fpSub, bytes: fpSub },
    fpMul: { ops: fpMul, bytes: fpMul },
    fpSqr: { ops: fpSqr, bytes: fpSqr },
    fpNeg: { ops: fpNeg, bytes: fpNeg },
    fpInv: { ops: fpInv, bytes: fpInv },
  };
}

/**
 * Detailed Groth16 verifier size estimate with BSV optimizations.
 *
 * Key optimizations over naive approach:
 * 1. Altstack P caching (3 bytes per P access vs 34 bytes for fresh push)
 * 2. Sparse Fp12 multiplication in Miller loop (line elements are sparse)
 * 3. Multi-Miller loop (4 pairings share the same loop structure)
 * 4. Precomputed VK constants (known at compile time)
 * 5. NAF (non-adjacent form) for Miller loop parameter
 */
export function estimateOptimizedVerifierSize(numPublicInputs: number): {
  totalBytes: number;
  totalKB: number;
  breakdown: Record<string, number>;
} {
  const sizes = estimateOpSizes();
  const fpMul = sizes.fpMul!.bytes;
  const fpAdd = sizes.fpAdd!.bytes;
  const fpSub = sizes.fpSub!.bytes;
  const fpInv = sizes.fpInv!.bytes;

  // Stack management overhead per composite operation (~4 bytes avg for PICK/ROLL/SWAP)
  const STACK_OVERHEAD = 4;

  // --- Fp2 multiplication (Karatsuba) ---
  // t0 = a0*b0, t1 = a1*b1, c0 = t0-t1, c1 = (a0+a1)(b0+b1)-t0-t1
  // 3 fpMul + 2 fpAdd + 3 fpSub + stack management
  const fp2Mul = 3 * fpMul + 2 * fpAdd + 3 * fpSub + 6 * STACK_OVERHEAD;

  // Fp2 squaring (complex squaring: cheaper)
  const fp2Sqr = 2 * fpMul + 2 * fpAdd + 1 * fpSub + 4 * STACK_OVERHEAD;

  // Fp2 add/sub
  const fp2Add = 2 * fpAdd + STACK_OVERHEAD;
  const fp2Sub = 2 * fpSub + STACK_OVERHEAD;

  // Fp2 mul by nonresidue ξ = 9+u: (a0+a1u)(9+u) = (9a0-a1) + (a0+9a1)u
  // 2 fpMul(by 9, but 9 is small — just shift+add) + 1 fpAdd + 1 fpSub
  const fp2MulXi = 2 * fpMul + fpAdd + fpSub + 2 * STACK_OVERHEAD;

  // --- Fp6 multiplication (Karatsuba on Fp2) ---
  // 6 Fp2 muls + several Fp2 add/sub + mulByXi
  const fp6Mul = 6 * fp2Mul + 9 * fp2Add + 3 * fp2Sub + fp2MulXi + 8 * STACK_OVERHEAD;

  // Fp6 squaring
  const fp6Sqr = 4 * fp2Sqr + 4 * fp2Mul + 4 * fp2Add + fp2MulXi + 6 * STACK_OVERHEAD;

  // --- Fp12 multiplication ---
  // 3 Fp6 muls + Fp6 add/sub + mulByV (similar to mulByXi)
  const fp12Mul = 3 * fp6Mul + 2 * (3 * fp2Add) + fp2MulXi + 6 * STACK_OVERHEAD;

  // Fp12 squaring
  const fp12Sqr = 2 * fp6Sqr + fp6Mul + 2 * (3 * fp2Add) + 4 * STACK_OVERHEAD;

  // --- Sparse Fp12 multiplication (Miller loop line evaluation) ---
  // Line elements have only 3 nonzero Fp2 components.
  // Sparse × dense ≈ 13 Fp2 muls (vs 18 for general)
  const fp12SparseMul = 13 * fp2Mul + 8 * fp2Add + 3 * fp2Sub + fp2MulXi + 8 * STACK_OVERHEAD;

  // --- Miller loop (multi-pairing, 4 pairs simultaneously) ---
  // 63 iterations of 6x+2 (BN parameter). Using NAF reduces to ~50 effective iterations.
  const millerIterations = 50; // NAF-optimized

  // Per iteration: 1 Fp12 sqr + 4 × line evaluation + 4 × sparse Fp12 mul
  // Line evaluation (doubling step): ~6 Fp2 muls + adds ≈ 6 * fp2Mul
  const lineEvalDouble = 6 * fp2Mul + 4 * fp2Add + 4 * STACK_OVERHEAD;
  // Line evaluation (addition step, ~30% of iterations): ~8 Fp2 muls
  const lineEvalAdd = 8 * fp2Mul + 6 * fp2Add + 4 * STACK_OVERHEAD;

  // Per iteration (doubling only):
  const millerIterDouble = fp12Sqr + 4 * lineEvalDouble + 4 * fp12SparseMul;
  // Per iteration (with addition): add 4 lineEvalAdd + 4 fp12SparseMul
  const millerIterAdd = millerIterDouble + 4 * lineEvalAdd + 4 * fp12SparseMul;

  // ~50 iterations, ~30% have addition steps
  const millerLoop = Math.ceil(millerIterations * 0.7) * millerIterDouble +
                     Math.ceil(millerIterations * 0.3) * millerIterAdd;

  // --- Final exponentiation ---
  // Easy part: f^{p^6-1} × f^{p^2+1} = 2 Fp12 inversions + 2 Fp12 muls + Frobenius
  // Fp12 inv ≈ Fp6 inv + Fp6 mul ≈ (6*fp2Mul + fp2Inv + ...) ≈ fpInv + 10*fp2Mul
  const fp12Inv = fpInv + 10 * fp2Mul + 6 * STACK_OVERHEAD;
  const frobeniusMap = 6 * fp2Mul + 6 * STACK_OVERHEAD; // multiply each Fp2 by precomputed constant

  const finalExpEasy = 2 * fp12Inv + 2 * fp12Mul + 2 * frobeniusMap;

  // Hard part: f^{(p^4-p^2+1)/r} using BN-specific formula
  // Requires: ~12 Fp12 squarings + ~4 Fp12 muls + 3 Frobenius + 2 Fp12 inversions
  const finalExpHard = 12 * fp12Sqr + 4 * fp12Mul + 3 * frobeniusMap + 2 * fp12Inv;

  const finalExp = finalExpEasy + finalExpHard;

  // --- IC computation ---
  // L = IC[0] + Σ input_i × IC[i+1]
  // Each scalar mul: 254 iterations × (G1 double ~4 fpMul + conditional G1 add ~6 fpMul)
  // With precomputed table (window-4): 254/4 = 64 lookups × ~6 fpMul
  const g1ScalarMul = 64 * (6 * fpMul + 4 * fpAdd + 2 * STACK_OVERHEAD);
  const icComputation = numPublicInputs * g1ScalarMul + (numPublicInputs - 1) * (6 * fpMul + 4 * fpAdd);

  // --- VK embedding ---
  // Verification key constants: alpha(64B) + beta(128B) + gamma(128B) + delta(128B) + IC
  const vkEmbedding = 64 + 128 * 3 + (numPublicInputs + 1) * 64;

  // --- Initial P push + cleanup ---
  const pSetup = 34 + 2; // push P (34 bytes) + TOALTSTACK (1) + final FROMALTSTACK+DROP (2)

  const totalBytes = pSetup + vkEmbedding + icComputation + millerLoop + finalExp;

  return {
    totalBytes,
    totalKB: Math.ceil(totalBytes / 1024),
    breakdown: {
      pSetupAndVK: pSetup + vkEmbedding,
      icComputation,
      millerLoop,
      finalExponentiation: finalExp,
      perFpMul: fpMul,
      perFp2Mul: fp2Mul,
      perFp12Mul: fp12Mul,
      perFp12SparseMul: fp12SparseMul,
      perFp12Sqr: fp12Sqr,
      perMillerIterDouble: millerIterDouble,
      perFpInv: fpInv,
    },
  };
}
