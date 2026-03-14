/**
 * BN254 Fp12 extension field arithmetic -> Bitcoin Script codegen.
 *
 * Fp12 = Fp6[w] / (w^2 - v). Each element is a pair (c0, c1) of Fp6
 * elements, representing c0 + c1*w where w^2 = v.
 *
 * Since each Fp6 is 6 Fp slots, an Fp12 element occupies 12 Fp stack slots.
 *
 * ## Stack convention
 *
 * An Fp12 element (12 Fp slots, bottom to top):
 *   [..., c0_0_0, c0_0_1, c0_1_0, c0_1_1, c0_2_0, c0_2_1,
 *         c1_0_0, c1_0_1, c1_1_0, c1_1_1, c1_2_0, c1_2_1]
 *
 * c0 occupies slots 6-11 from TOS, c1 occupies slots 0-5 from TOS.
 *
 * The 6 Fp2 components indexed 0-5 (for Frobenius) map as:
 *   0: c0.c0 (slots 10-11)
 *   1: c0.c1 (slots 8-9)
 *   2: c0.c2 (slots 6-7)
 *   3: c1.c0 (slots 4-5)
 *   4: c1.c1 (slots 2-3)
 *   5: c1.c2 (slots 0-1)
 *
 * ## Key identity: w^2 = v
 *
 * In the Fp12 reduction, multiplying an Fp6 element by v applies a cyclic
 * shift: (c0, c1, c2) * v = (xi*c2, c0, c1).
 *
 * ## Implementation strategy
 *
 * All operations use the "recompute" approach: intermediate products are
 * recomputed per result component rather than cached on the altstack.
 * This trades extra Fp2/Fp6 multiplications for clean stack management.
 * A future optimized version can cache shared subexpressions.
 *
 * ## Frobenius endomorphism
 *
 * The p-th power Frobenius map acts on each Fp2 component by conjugation
 * followed by multiplication by a precomputed constant. The p^2 map uses
 * different constants and no conjugation (since conjugating twice is identity).
 *
 * ## Sparse multiplication
 *
 * Miller loop line evaluations produce sparse Fp12 elements with only 3
 * nonzero Fp2 components. The sparse multiply constructs a full Fp12 from
 * these components and delegates to general multiplication. A future
 * optimized version would exploit the sparsity structure directly.
 */

import type { StackOp } from 'runar-ir-schema';
import { emitPushFp } from './field-script.js';
import {
  emitFp2Mul, emitFp2Conj, emitFp2MulScalar,
  emitPushFp2, emitToAltFp2, emitFromAltFp2,
  emitRoll, emitPick, emitToAlt, emitFromAlt, emitDrop,
} from './fp2-script.js';
import {
  emitFp6Add, emitFp6Sub, emitFp6Neg, emitFp6Mul, emitFp6Sqr, emitFp6MulByV,
  emitFp6Inv,
} from './fp6-script.js';

// ---------------------------------------------------------------------------
// Fp6 block helpers
// ---------------------------------------------------------------------------

/**
 * Copy an Fp6 (6 Fp slots) whose topmost slot is at `depth` from TOS.
 * Pushes a copy on top of the stack (6 new slots).
 */
function emitPickFp6(ops: StackOp[], depth: number): void {
  for (let i = 0; i < 6; i++) {
    emitPick(ops, depth + 5);
  }
}

/**
 * Roll an Fp6 (6 slots) from `depth` to top of stack.
 */
function emitRollFp6(ops: StackOp[], depth: number): void {
  for (let i = 0; i < 6; i++) {
    emitRoll(ops, depth + 5);
  }
}

/** Save top Fp6 (6 slots) to altstack. */
function emitToAltFp6(ops: StackOp[]): void {
  for (let i = 0; i < 6; i++) emitToAlt(ops);
}

/** Restore Fp6 from altstack. */
function emitFromAltFp6(ops: StackOp[]): void {
  for (let i = 0; i < 6; i++) emitFromAlt(ops);
}

/** Drop top Fp6 (6 slots). */
function emitDropFp6(ops: StackOp[]): void {
  for (let i = 0; i < 6; i++) emitDrop(ops);
}

// ---------------------------------------------------------------------------
// Frobenius constants (precomputed for BN254)
// ---------------------------------------------------------------------------

/**
 * Frobenius p: gamma constants for each of the 6 Fp2 components.
 * Components [1, v, v², w, vw, v²w] need exponents [0, 2, 4, 1, 3, 5] × (p-1)/6.
 * gamma_i = xi^{e_i*(p-1)/6} where xi = 9+u and e = [0,2,4,1,3,5].
 */
const FROBENIUS_P_COEFFS: Array<[bigint, bigint]> = [
  // Component 0 (1): xi^{0*(p-1)/6} = 1
  [1n, 0n],
  // Component 1 (v): xi^{2*(p-1)/6}
  [
    21575463638280843010398324269430826099269044274347216827212613867836435027261n,
    10307601595873709700152284273816112264069230130616436755625194854815875713954n,
  ],
  // Component 2 (v²): xi^{4*(p-1)/6}
  [
    2581911344467009335267311115468803099551665605076196740867805258568234346338n,
    19937756971775647987995932169929341994314640652964949448313374472400716661030n,
  ],
  // Component 3 (w): xi^{1*(p-1)/6}
  [
    8376118865763821496583973867626364092589906065868298776909617916018768340080n,
    16469823323077808223889137241176536799009286646108169935659301613961712198316n,
  ],
  // Component 4 (vw): xi^{3*(p-1)/6}
  [
    2821565182194536844548159561693502659359617185244120367078079554186484126554n,
    3505843767911556378687030309984248845540243509899259641013678093033130930403n,
  ],
  // Component 5 (v²w): xi^{5*(p-1)/6}
  [
    685108087231508774477564247770172212460312782337200605669322048753928464687n,
    8447204650696766136447902020341177575205426561248465145919723016860428151883n,
  ],
];

/**
 * Frobenius p^2: gamma constants. All are real (c1=0) for BN254.
 * Components [1, v, v², w, vw, v²w] need exponents [0, 2, 4, 1, 3, 5] × (p²-1)/6.
 */
const FROBENIUS_P2_COEFFS: Array<[bigint, bigint]> = [
  // Component 0 (1): 1
  [1n, 0n],
  // Component 1 (v): xi^{2*(p²-1)/6}
  [21888242871839275220042445260109153167277707414472061641714758635765020556616n, 0n],
  // Component 2 (v²): xi^{4*(p²-1)/6}
  [2203960485148121921418603742825762020974279258880205651966n, 0n],
  // Component 3 (w): xi^{1*(p²-1)/6}
  [21888242871839275220042445260109153167277707414472061641714758635765020556617n, 0n],
  // Component 4 (vw): xi^{3*(p²-1)/6}
  [21888242871839275222246405745257275088696311157297823662689037894645226208582n, 0n],
  // Component 5 (v²w): xi^{5*(p²-1)/6}
  [2203960485148121921418603742825762020974279258880205651967n, 0n],
];

// ---------------------------------------------------------------------------
// Fp12 multiplication
// ---------------------------------------------------------------------------

/**
 * Fp12 multiplication.
 *
 * Given f = (a0, a1) and g = (b0, b1) in Fp6 pairs:
 *   c0 = a0*b0 + mulByV(a1*b1)
 *   c1 = (a0+a1)(b0+b1) - a0*b0 - a1*b1
 *
 * Uses the recompute strategy: a0*b0 and a1*b1 are recomputed for each
 * result component rather than cached.
 *
 * Stack: [..., f(12), g(12)] -> [..., result(12)]
 *
 * Input layout (24 Fp slots): a0 at 18-23, a1 at 12-17, b0 at 6-11, b1 at 0-5.
 */
export function emitFp12Mul(ops: StackOp[]): void {
  // ---- c0 = a0*b0 + mulByV(a1*b1) ----

  // a0*b0
  emitPickFp6(ops, 18); emitPickFp6(ops, 12); emitFp6Mul(ops);
  emitToAltFp6(ops);      // alt: [P, a0b0]

  // mulByV(a1*b1)
  emitPickFp6(ops, 12); emitPickFp6(ops, 6); emitFp6Mul(ops);
  emitFp6MulByV(ops);

  // c0 = a0b0 + mulByV(a1b1)
  emitFromAltFp6(ops);   // [..., mulByV(a1b1), a0b0]
  emitFp6Add(ops);        // [..., c0]
  emitToAltFp6(ops);      // alt: [P, c0]

  // ---- c1 = (a0+a1)(b0+b1) - a0*b0 - a1*b1 ----

  // (a0+a1)
  emitPickFp6(ops, 18); emitPickFp6(ops, 18); emitFp6Add(ops);
  // (b0+b1)
  emitPickFp6(ops, 12); emitPickFp6(ops, 12); emitFp6Add(ops);
  emitFp6Mul(ops);        // (a0+a1)(b0+b1)

  // - a0*b0 (stack has 30 slots: originals(24) + cross(6))
  emitPickFp6(ops, 24); emitPickFp6(ops, 18); emitFp6Mul(ops);
  emitFp6Sub(ops);

  // - a1*b1 (stack still 30 slots: originals(24) + (cross-a0b0)(6))
  emitPickFp6(ops, 18); emitPickFp6(ops, 12); emitFp6Mul(ops);
  emitFp6Sub(ops);        // c1

  // Save c1, drop originals, restore results
  emitToAltFp6(ops);      // alt: [P, c0, c1]
  emitDropFp6(ops); emitDropFp6(ops); emitDropFp6(ops); emitDropFp6(ops);

  // Restore: LIFO pops c1 first, then c0
  emitFromAltFp6(ops);   // [c1]
  emitFromAltFp6(ops);   // [c1, c0]  (c0 on top)
  emitRollFp6(ops, 6);   // [c0, c1]
}

// ---------------------------------------------------------------------------
// Fp12 squaring
// ---------------------------------------------------------------------------

/**
 * Fp12 squaring. Duplicates the input and delegates to multiplication.
 *
 * Stack: [..., f(12)] -> [..., f^2(12)]
 */
export function emitFp12Sqr(ops: StackOp[]): void {
  // Duplicate 12 slots: copy c0 (at depth 6), then c1 (shifted)
  emitPickFp6(ops, 6);   // copy c0
  emitPickFp6(ops, 6);   // copy c1 (shifted +6 by c0 copy)
  // Stack: [c0, c1, c0, c1]
  emitFp12Mul(ops);
}

// ---------------------------------------------------------------------------
// Fp12 inverse
// ---------------------------------------------------------------------------

/**
 * Fp12 inverse.
 *
 * Given f = (c0, c1) where c0 and c1 are Fp6 elements:
 *   c0s = c0^2
 *   c1s = c1^2
 *   c1sv = mulByV(c1s)   -- multiply Fp6 by v: (xi*c2, c0, c1)
 *   det = c0s - c1sv
 *   detInv = fp6Inv(det)
 *   result_c0 = c0 * detInv
 *   result_c1 = -(c1 * detInv)
 *
 * Stack: [..., c0(6), c1(6)] -> [..., inv_c0(6), inv_c1(6)]
 */
export function emitFp12Inv(ops: StackOp[]): void {
  // Input layout (from TOS): c1 at 0-5, c0 at 6-11 (12 Fp slots)

  // ---- det = c0^2 - mulByV(c1^2) ----

  // c0^2
  emitPickFp6(ops, 6);    // copy c0
  emitFp6Sqr(ops);         // c0^2
  emitToAltFp6(ops);       // alt: [P, c0s]

  // mulByV(c1^2)
  emitPickFp6(ops, 0);    // copy c1
  emitFp6Sqr(ops);         // c1^2
  emitFp6MulByV(ops);      // mulByV(c1^2)

  // det = c0s - c1sv
  emitFromAltFp6(ops);    // c0s from alt. alt: [P]
  // Stack: [..., c0, c1, c1sv, c0s]
  // Need c0s - c1sv, so roll c1sv up and subtract
  emitRollFp6(ops, 6);    // [..., c0, c1, c0s, c1sv]
  emitFp6Sub(ops);          // [..., c0, c1, det]

  // ---- detInv = fp6Inv(det) ----
  emitFp6Inv(ops);          // [..., c0, c1, detInv]

  // ---- result_c0 = c0 * detInv ----
  emitPickFp6(ops, 12);   // copy c0 (shifted +6 by detInv)
  emitPickFp6(ops, 6);    // copy detInv (shifted +6 by c0 copy)
  emitFp6Mul(ops);          // result_c0
  emitToAltFp6(ops);       // alt: [P, result_c0]

  // ---- result_c1 = -(c1 * detInv) ----
  // Stack: [..., c0, c1, detInv]
  // emitFp6Mul consumes top two Fp6 values: c1 * detInv
  emitFp6Mul(ops);          // [..., c0, c1*detInv]
  emitFp6Neg(ops);          // [..., c0, -(c1*detInv)]
  emitToAltFp6(ops);       // alt: [P, result_c0, result_c1]

  // Drop original c0 (6 slots)
  emitDropFp6(ops);

  // Restore results: LIFO pops result_c1 first, then result_c0
  emitFromAltFp6(ops);    // result_c1. alt: [P, result_c0]
  emitFromAltFp6(ops);    // result_c0. alt: [P]
  // Stack: [..., result_c1, result_c0]
  // Need: [..., result_c0, result_c1]
  emitRollFp6(ops, 6);    // [..., result_c0, result_c1]
}

// ---------------------------------------------------------------------------
// Fp12 conjugate
// ---------------------------------------------------------------------------

/**
 * Fp12 conjugate: (c0, -c1).
 *
 * For unitary elements, conjugate equals inverse.
 *
 * Stack: [..., c0(6), c1(6)] -> [..., c0(6), -c1(6)]
 */
export function emitFp12Conj(ops: StackOp[]): void {
  emitFp6Neg(ops);
}

// ---------------------------------------------------------------------------
// Sparse Fp12 multiplication (Miller loop)
// ---------------------------------------------------------------------------

/**
 * Sparse Fp12 multiplication for Miller loop line evaluations.
 *
 * A line evaluation produces a sparse Fp12 with only 3 nonzero Fp2
 * components. In Fp6 notation:
 *   sparse.c0 = (s0, 0, 0)     -- only the constant term of c0
 *   sparse.c1 = (s1, s2, 0)    -- two terms of c1
 *
 * For the initial implementation, we construct the full Fp12 from the
 * 3 sparse Fp2 values and delegate to general multiplication.
 *
 * A future optimized version would exploit sparsity for ~13 Fp2 muls
 * instead of the 18+ in general Fp12 mul.
 *
 * Stack: [..., f(12), s0(2), s1(2), s2(2)] -> [..., result(12)]
 */
export function emitFp12SparseMul(ops: StackOp[]): void {
  // s2 at 0-1, s1 at 2-3, s0 at 4-5, f at 6-17 from TOS

  // Save s0, s1, s2 to altstack
  emitToAltFp2(ops);      // save s2. alt: [P, s2]
  emitToAltFp2(ops);      // save s1. alt: [P, s2, s1]
  emitToAltFp2(ops);      // save s0. alt: [P, s2, s1, s0]

  // Build sparse.c0 = (s0, 0, 0)
  emitFromAltFp2(ops);   // [f(12), s0]. alt: [P, s2, s1]
  emitPushFp2(ops, 0n, 0n);
  emitPushFp2(ops, 0n, 0n);
  // Stack: [f(12), c0_sparse(6)] = [f(12), s0, 0, 0]

  // Build sparse.c1 = (s1, s2, 0)
  emitFromAltFp2(ops);   // s1. alt: [P, s2]
  emitFromAltFp2(ops);   // s2. alt: [P]
  emitPushFp2(ops, 0n, 0n);
  // Stack: [f(12), c0_sparse(6), c1_sparse(6)] = [f(12), sparse(12)]

  emitFp12Mul(ops);
}

// ---------------------------------------------------------------------------
// Frobenius endomorphisms
// ---------------------------------------------------------------------------

/**
 * Frobenius p-th power map.
 *
 * For each Fp2 component i (0..5) of the Fp12 element:
 *   result_i = conj(c_i) * gamma_i
 *
 * where conj is Fp2 conjugation and gamma_i are precomputed constants.
 *
 * Stack: [..., f(12)] -> [..., f^p(12)]
 */
export function emitFp12FrobeniusP(ops: StackOp[]): void {
  // Process components from top (index 5) to bottom (index 0).
  // Each iteration: the current top Fp2 is component i.
  // Conjugate it, multiply by gamma_i, save to altstack.
  for (let i = 5; i >= 0; i--) {
    emitFp2Conj(ops);

    const [g0, g1] = FROBENIUS_P_COEFFS[i]!;
    if (g0 !== 1n || g1 !== 0n) {
      if (g1 === 0n) {
        // Real constant: scalar multiply
        emitPushFp(ops, g0);
        emitFp2MulScalar(ops);
      } else {
        // Full Fp2 constant multiply
        emitPushFp2(ops, g0, g1);
        emitFp2Mul(ops);
      }
    }

    emitToAltFp2(ops);
  }

  // Restore all 6 components (component 0 pops first since it was pushed last)
  for (let i = 0; i < 6; i++) {
    emitFromAltFp2(ops);
  }
}

/**
 * Frobenius p^2-th power map.
 *
 * For BN254, the p^2 Frobenius constants are all real (c1=0), and
 * p^2 conjugation is the identity. So this is purely scalar
 * multiplication of each Fp2 component.
 *
 * Stack: [..., f(12)] -> [..., f^{p^2}(12)]
 */
export function emitFp12FrobeniusP2(ops: StackOp[]): void {
  for (let i = 5; i >= 0; i--) {
    const [g0, _g1] = FROBENIUS_P2_COEFFS[i]!;
    if (g0 !== 1n) {
      emitPushFp(ops, g0);
      emitFp2MulScalar(ops);
    }
    // If g0 === 1n, this component is unchanged.

    emitToAltFp2(ops);
  }

  for (let i = 0; i < 6; i++) {
    emitFromAltFp2(ops);
  }
}
