/**
 * BN254 Fp6 extension field arithmetic -> Bitcoin Script codegen.
 *
 * Fp6 = Fp2[v] / (v^3 - xi) where xi = 9 + u (the Fp2 non-residue).
 *
 * Each Fp6 element is a triple (c0, c1, c2) of Fp2 elements, representing
 * c0 + c1*v + c2*v^2. Since each Fp2 is 2 stack slots, an Fp6 element
 * occupies 6 stack slots total.
 *
 * ## Stack convention
 *
 * An Fp6 element on the stack (6 Fp slots, bottom to top):
 *   [..., c0_0, c0_1, c1_0, c1_1, c2_0, c2_1]
 *
 * c2_1 is on top. Each (ci_0, ci_1) pair is an Fp2 element.
 *
 * ## Key identity: v^3 = xi
 *
 * Multiplying by v cyclically shifts coefficients:
 *   (c0, c1, c2) * v = (xi*c2, c0, c1)
 *
 * ## Multiplication strategy
 *
 * Uses Karatsuba over Fp2. For cleanliness of stack management, the
 * implementation uses a "recompute" approach that recomputes some
 * intermediate products rather than juggling 3 Fp2 temporaries across
 * all 3 result components. This uses 15 Fp2 muls (vs optimal 6) but
 * keeps the stack logic correct and auditable. A future optimized
 * version can cache t0/t1/t2 using deeper altstack management.
 *
 * ## Altstack usage
 *
 * P remains on the altstack throughout. Intermediate Fp2 results are
 * stored above P on the altstack and always restored before returning.
 */

import type { StackOp } from 'runar-ir-schema';
import {
  emitFp2Add, emitFp2Sub, emitFp2Neg, emitFp2Mul, emitFp2Sqr, emitFp2Inv,
  emitFp2MulByXi,
  emitPickFp2, emitRollFp2, emitToAltFp2, emitFromAltFp2, emitDropFp2,
  emitRoll,
} from './fp2-script.js';

// ---------------------------------------------------------------------------
// Fp6 addition
// ---------------------------------------------------------------------------

/**
 * Fp6 addition: component-wise Fp2 addition.
 *
 * Stack: [..., a0, a1, a2, b0, b1, b2] (12 Fp slots)
 *     -> [..., r0, r1, r2] (6 Fp slots)
 *
 * Strategy: compute each component sum, saving results to altstack,
 * then drop originals and restore results.
 */
export function emitFp6Add(ops: StackOp[]): void {
  // Layout (slot index from top): b2=0, b1=2, b0=4, a2=6, a1=8, a0=10

  // r2 = a2 + b2
  emitPickFp2(ops, 6);   // copy a2 -> top
  emitPickFp2(ops, 2);   // copy b2 (shifted +2 by a2 copy)
  emitFp2Add(ops);        // [originals..., r2]
  emitToAltFp2(ops);      // alt: [P, r2]

  // r1 = a1 + b1
  emitPickFp2(ops, 8);   // copy a1
  emitPickFp2(ops, 4);   // copy b1 (shifted +2)
  emitFp2Add(ops);
  emitToAltFp2(ops);      // alt: [P, r2, r1]

  // r0 = a0 + b0
  emitPickFp2(ops, 10);  // copy a0
  emitPickFp2(ops, 6);   // copy b0 (shifted +2)
  emitFp2Add(ops);
  emitToAltFp2(ops);      // alt: [P, r2, r1, r0]

  // Drop 12 original slots
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);

  // Restore results: r0 first (deepest), then r1, r2
  emitFromAltFp2(ops);   // [r0]
  emitFromAltFp2(ops);   // [r0, r1]
  emitFromAltFp2(ops);   // [r0, r1, r2]
}

// ---------------------------------------------------------------------------
// Fp6 subtraction
// ---------------------------------------------------------------------------

/**
 * Fp6 subtraction: component-wise Fp2 subtraction.
 *
 * Stack: [..., a0, a1, a2, b0, b1, b2] -> [..., r0, r1, r2]
 */
export function emitFp6Sub(ops: StackOp[]): void {
  // r2 = a2 - b2
  emitPickFp2(ops, 6);   // copy a2
  emitPickFp2(ops, 2);   // copy b2
  emitFp2Sub(ops);
  emitToAltFp2(ops);

  // r1 = a1 - b1
  emitPickFp2(ops, 8);
  emitPickFp2(ops, 4);
  emitFp2Sub(ops);
  emitToAltFp2(ops);

  // r0 = a0 - b0
  emitPickFp2(ops, 10);
  emitPickFp2(ops, 6);
  emitFp2Sub(ops);
  emitToAltFp2(ops);

  // Drop 12 original slots
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);

  // Restore
  emitFromAltFp2(ops);
  emitFromAltFp2(ops);
  emitFromAltFp2(ops);
}

// ---------------------------------------------------------------------------
// Fp6 negation
// ---------------------------------------------------------------------------

/**
 * Fp6 negation: component-wise Fp2 negation.
 *
 * Stack: [..., c0, c1, c2] -> [..., -c0, -c1, -c2]
 */
export function emitFp6Neg(ops: StackOp[]): void {
  // Negate c2 (top), save
  emitFp2Neg(ops);
  emitToAltFp2(ops);      // alt: [P, -c2]

  // Negate c1, save
  emitFp2Neg(ops);
  emitToAltFp2(ops);      // alt: [P, -c2, -c1]

  // Negate c0
  emitFp2Neg(ops);        // [-c0]

  // Restore
  emitFromAltFp2(ops);   // [-c0, -c1]
  emitFromAltFp2(ops);   // [-c0, -c1, -c2]
}

// ---------------------------------------------------------------------------
// Fp6 multiply by v
// ---------------------------------------------------------------------------

/**
 * Multiply Fp6 by v: cyclic shift with xi multiply.
 *
 * (c0, c1, c2) * v = (xi*c2, c0, c1)
 *
 * Stack: [..., c0_0, c0_1, c1_0, c1_1, c2_0, c2_1]
 *     -> [..., (xi*c2)_0, (xi*c2)_1, c0_0, c0_1, c1_0, c1_1]
 */
export function emitFp6MulByV(ops: StackOp[]): void {
  // Stack: [c0_0, c0_1, c1_0, c1_1, c2_0, c2_1]
  // Multiply c2 by xi
  emitFp2MulByXi(ops);   // [c0_0, c0_1, c1_0, c1_1, xc2_0, xc2_1]

  // Need to rotate: [xc2, c0, c1]
  // Current: [c0_0, c0_1, c1_0, c1_1, xc2_0, xc2_1]
  // Target:  [xc2_0, xc2_1, c0_0, c0_1, c1_0, c1_1]
  // Rotate 4 positions: roll each of the bottom 4 elements to the top
  emitRoll(ops, 5);       // [c0_1, c1_0, c1_1, xc2_0, xc2_1, c0_0]
  emitRoll(ops, 5);       // [c1_0, c1_1, xc2_0, xc2_1, c0_0, c0_1]
  emitRoll(ops, 5);       // [c1_1, xc2_0, xc2_1, c0_0, c0_1, c1_0]
  emitRoll(ops, 5);       // [xc2_0, xc2_1, c0_0, c0_1, c1_0, c1_1]
}

// ---------------------------------------------------------------------------
// Fp6 multiplication
// ---------------------------------------------------------------------------

/**
 * Fp6 multiplication using Karatsuba over Fp2.
 *
 * Given a = (a0, a1, a2), b = (b0, b1, b2):
 *   t0 = a0*b0, t1 = a1*b1, t2 = a2*b2
 *   r0 = t0 + xi*((a1+a2)(b1+b2) - t1 - t2)
 *   r1 = (a0+a1)(b0+b1) - t0 - t1 + xi*t2
 *   r2 = (a0+a2)(b0+b2) - t0 - t2 + t1
 *
 * Each result component recomputes the base products (t0=a0*b0, t1=a1*b1,
 * t2=a2*b2) from the originals rather than caching them. This trades ~9
 * extra Fp2 muls for clean, auditable stack logic.
 *
 * Results are computed in order r2, r1, r0 so that LIFO alt pops give
 * the correct [r0, r1, r2] layout without post-reordering.
 *
 * Stack: [..., a0, a1, a2, b0, b1, b2] (12 Fp slots)
 *     -> [..., r0, r1, r2] (6 Fp slots)
 */
export function emitFp6Mul(ops: StackOp[]): void {
  // Base depths of original 12-slot input (b2 on top):
  // a0=10, a1=8, a2=6, b0=4, b1=2, b2=0
  //
  // 'e' tracks extra Fp slots above the originals on the main stack.
  // pick: e+=2. Fp2 binary op (add/sub/mul): e-=2. mulByXi/sqr/neg: e+=0.
  // toAlt: e-=2. fromAlt: e+=2.
  let e = 0;

  // ==== r2 = (a0+a2)(b0+b2) - a0*b0 - a2*b2 + a1*b1 ====

  // (a0+a2)
  emitPickFp2(ops, 10 + e); e += 2;  // a0
  emitPickFp2(ops, 6 + e);  e += 2;  // a2
  emitFp2Add(ops);           e -= 2;  // e=2

  // (b0+b2)
  emitPickFp2(ops, 4 + e);  e += 2;  // b0
  emitPickFp2(ops, 0 + e);  e += 2;  // b2
  emitFp2Add(ops);           e -= 2;  // e=4

  emitFp2Mul(ops);           e -= 2;  // cross=(a0+a2)*(b0+b2). e=2

  // - a0*b0
  emitPickFp2(ops, 10 + e); e += 2;
  emitPickFp2(ops, 4 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // - a2*b2
  emitPickFp2(ops, 6 + e);  e += 2;
  emitPickFp2(ops, 0 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // + a1*b1
  emitPickFp2(ops, 8 + e);  e += 2;
  emitPickFp2(ops, 2 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Add(ops);           e -= 2;  // e=2, r2 on stack

  emitToAltFp2(ops);         e -= 2;  // e=0, alt: [r2]

  // ==== r1 = (a0+a1)(b0+b1) - a0*b0 - a1*b1 + xi*a2*b2 ====

  // (a0+a1)
  emitPickFp2(ops, 10 + e); e += 2;
  emitPickFp2(ops, 8 + e);  e += 2;
  emitFp2Add(ops);           e -= 2;  // e=2

  // (b0+b1)
  emitPickFp2(ops, 4 + e);  e += 2;
  emitPickFp2(ops, 2 + e);  e += 2;
  emitFp2Add(ops);           e -= 2;  // e=4

  emitFp2Mul(ops);           e -= 2;  // e=2

  // - a0*b0
  emitPickFp2(ops, 10 + e); e += 2;
  emitPickFp2(ops, 4 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // - a1*b1
  emitPickFp2(ops, 8 + e);  e += 2;
  emitPickFp2(ops, 2 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // + xi*a2*b2
  emitPickFp2(ops, 6 + e);  e += 2;
  emitPickFp2(ops, 0 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2MulByXi(ops);               // e=4
  emitFp2Add(ops);           e -= 2;  // e=2, r1 on stack

  emitToAltFp2(ops);         e -= 2;  // e=0, alt: [r2, r1]

  // ==== r0 = a0*b0 + xi*((a1+a2)(b1+b2) - a1*b1 - a2*b2) ====

  // (a1+a2)
  emitPickFp2(ops, 8 + e);  e += 2;
  emitPickFp2(ops, 6 + e);  e += 2;
  emitFp2Add(ops);           e -= 2;  // e=2

  // (b1+b2)
  emitPickFp2(ops, 2 + e);  e += 2;
  emitPickFp2(ops, 0 + e);  e += 2;
  emitFp2Add(ops);           e -= 2;  // e=4

  emitFp2Mul(ops);           e -= 2;  // cross. e=2

  // - a1*b1
  emitPickFp2(ops, 8 + e);  e += 2;
  emitPickFp2(ops, 2 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // - a2*b2
  emitPickFp2(ops, 6 + e);  e += 2;
  emitPickFp2(ops, 0 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Sub(ops);           e -= 2;  // e=2

  // * xi
  emitFp2MulByXi(ops);               // e=2

  // + a0*b0
  emitPickFp2(ops, 10 + e); e += 2;
  emitPickFp2(ops, 4 + e);  e += 2;
  emitFp2Mul(ops);           e -= 2;  // e=4
  emitFp2Add(ops);           e -= 2;  // e=2, r0 on stack

  emitToAltFp2(ops);         e -= 2;  // e=0, alt: [r2, r1, r0]

  // Drop 12 original slots
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);
  emitDropFp2(ops); emitDropFp2(ops); emitDropFp2(ops);

  // Restore: LIFO pops r0, r1, r2 → [r0, r1, r2] (correct order)
  emitFromAltFp2(ops);   // [r0]
  emitFromAltFp2(ops);   // [r0, r1]
  emitFromAltFp2(ops);   // [r0, r1, r2]
}

// ---------------------------------------------------------------------------
// Fp6 squaring
// ---------------------------------------------------------------------------

/**
 * Fp6 squaring. Uses the formula from pairing.ts (fp6Sqr delegates to fp6Mul
 * there too). For a first correct implementation, we delegate to emitFp6Mul
 * by duplicating the input.
 *
 * Stack: [..., c0, c1, c2] (6 Fp slots)
 *     -> [..., r0, r1, r2] (6 Fp slots)
 *
 * A dedicated squaring formula (Chung-Hasan SQ2 or similar) would be
 * ~30% fewer Fp2 muls, but correctness first.
 */
export function emitFp6Sqr(ops: StackOp[]): void {
  // Duplicate the 6-slot Fp6 element
  emitPickFp2(ops, 4);   // copy c0
  emitPickFp2(ops, 4);   // copy c1 (shifted by 2)
  emitPickFp2(ops, 4);   // copy c2 (shifted by 4)
  // Stack: [c0, c1, c2, c0, c1, c2]
  emitFp6Mul(ops);
}

// ---------------------------------------------------------------------------
// Fp6 inverse
// ---------------------------------------------------------------------------

/**
 * Fp6 inverse using the adjugate matrix formula.
 *
 * Given a = (c0, c1, c2):
 *   c0s = c0^2,  c1s = c1^2,  c2s = c2^2
 *   t0 = c0s - xi*(c1*c2)
 *   t1 = xi*c2s - c0*c1
 *   t2 = c1s - c0*c2
 *   det = c0*t0 + xi*(c2*t1 + c1*t2)
 *   detInv = det^{-1}
 *   result = (t0*detInv, t1*detInv, t2*detInv)
 *
 * Stack: [..., c0, c1, c2] (6 Fp slots) -> [..., r0, r1, r2] (6 Fp slots)
 *
 * Strategy: compute t0, t1, t2 (saving to altstack), then compute det
 * from originals and t-values, invert it, then multiply each t by detInv.
 * Uses the recompute approach for clean stack management.
 */
export function emitFp6Inv(ops: StackOp[]): void {
  // Input layout (from TOS): c2=0, c1=2, c0=4
  // 6 Fp slots total for the input.

  // ---- t0 = c0^2 - xi*(c1*c2) ----
  emitPickFp2(ops, 4);   // copy c0
  emitFp2Sqr(ops);        // c0^2
  emitPickFp2(ops, 4);   // copy c1 (shifted +2 by c0^2)
  emitPickFp2(ops, 4);   // copy c2 (shifted +4)
  emitFp2Mul(ops);        // c1*c2
  emitFp2MulByXi(ops);   // xi*(c1*c2)
  emitFp2Sub(ops);        // t0 = c0^2 - xi*(c1*c2)
  emitToAltFp2(ops);      // alt: [P, t0]

  // ---- t1 = xi*c2^2 - c0*c1 ----
  emitPickFp2(ops, 0);   // copy c2
  emitFp2Sqr(ops);        // c2^2
  emitFp2MulByXi(ops);   // xi*c2^2
  emitPickFp2(ops, 6);   // copy c0 (shifted +2)
  emitPickFp2(ops, 6);   // copy c1 (shifted +4)
  emitFp2Mul(ops);        // c0*c1
  emitFp2Sub(ops);        // t1 = xi*c2^2 - c0*c1
  emitToAltFp2(ops);      // alt: [P, t0, t1]

  // ---- t2 = c1^2 - c0*c2 ----
  emitPickFp2(ops, 2);   // copy c1
  emitFp2Sqr(ops);        // c1^2
  emitPickFp2(ops, 6);   // copy c0 (shifted +2)
  emitPickFp2(ops, 4);   // copy c2 (shifted +4)
  emitFp2Mul(ops);        // c0*c2
  emitFp2Sub(ops);        // t2 = c1^2 - c0*c2
  emitToAltFp2(ops);      // alt: [P, t0, t1, t2]

  // ---- det = c0*t0 + xi*(c2*t1 + c1*t2) ----
  // Pop t2, t1, t0 from alt to main stack alongside original c0/c1/c2,
  // then save copies of t0/t1/t2 for the final detInv multiplication.

  emitPickFp2(ops, 4);   // copy c0
  emitFromAltFp2(ops);   // t2 from alt. alt: [P, t0, t1]
  emitFromAltFp2(ops);   // t1 from alt. alt: [P, t0]
  emitFromAltFp2(ops);   // t0 from alt. alt: [P]
  // Stack: [..., c0, c1, c2, c0_copy, t2, t1, t0]
  //         depths: 12  10    8    6    4   2   0

  // Save copies of t0, t1, t2 for later (push t2 first so t0 is on alt-top)
  emitPickFp2(ops, 4);   // copy t2
  emitToAltFp2(ops);      // alt: [P, t2_save]
  emitPickFp2(ops, 2);   // copy t1
  emitToAltFp2(ops);      // alt: [P, t2_save, t1_save]
  emitPickFp2(ops, 0);   // copy t0
  emitToAltFp2(ops);      // alt: [P, t2_save, t1_save, t0_save]

  // Stack still: [..., c0, c1, c2, c0_copy, t2, t1, t0]
  //               depths: 12  10    8    6    4   2   0

  // c0 * t0: roll c0_copy to top, then multiply
  emitRollFp2(ops, 6);   // [..., c0, c1, c2, t2, t1, t0, c0_copy]
  emitRollFp2(ops, 2);   // [..., c0, c1, c2, t2, t1, c0_copy, t0]
  emitFp2Mul(ops);        // [..., c0, c1, c2, t2, t1, c0*t0]
  emitToAltFp2(ops);      // alt: [P, t2_save, t1_save, t0_save, c0t0]
  // Stack: [..., c0, c1, c2, t2, t1]
  //         depths: 8   6    4   2   0

  // c2*t1
  emitPickFp2(ops, 4);   // copy c2
  emitRollFp2(ops, 2);   // roll t1 to top: [..., c0, c1, c2, t2, c2_copy, t1]
  emitFp2Mul(ops);        // [..., c0, c1, c2, t2, c2t1]

  // c1*t2
  emitPickFp2(ops, 6);   // copy c1 (c2t1=0, t2=2, c2=4, c1=6)
  emitRollFp2(ops, 4);   // roll t2 to top: [..., c0, c1, c2, c2t1, c1_copy, t2]
  emitFp2Mul(ops);        // [..., c0, c1, c2, c2t1, c1t2]

  // c2t1 + c1t2
  emitFp2Add(ops);        // [..., c0, c1, c2, sum]

  // xi * sum
  emitFp2MulByXi(ops);   // [..., c0, c1, c2, xi*sum]

  // + c0*t0
  emitFromAltFp2(ops);   // c0t0 from alt. alt: [P, t2_save, t1_save, t0_save]
  emitFp2Add(ops);        // [..., c0, c1, c2, det]

  // ---- detInv = det^{-1} ----
  emitFp2Inv(ops);        // [..., c0, c1, c2, detInv]

  // ---- r0 = t0*detInv, r1 = t1*detInv, r2 = t2*detInv ----
  // Pop t0, t1, t2 from alt (LIFO: t0 first since it was pushed last).
  emitFromAltFp2(ops);   // t0_save. alt: [P, t2_save, t1_save]
  emitFromAltFp2(ops);   // t1_save. alt: [P, t2_save]
  emitFromAltFp2(ops);   // t2_save. alt: [P]
  // Stack: [..., c0, c1, c2, detInv, t0, t1, t2]
  //         depths: 12  10    8    6    4   2   0

  // r2 = t2 * detInv
  // Stack: [..., c0, c1, c2, detInv, t0, t1, t2]
  //         depths: 12  10    8    6    4   2   0
  emitPickFp2(ops, 6);   // copy detInv
  emitFp2Mul(ops);        // [..., c0, c1, c2, detInv, t0, t1, r2]
  emitToAltFp2(ops);      // alt: [P, r2]

  // r1 = t1 * detInv
  // Stack: [..., c0, c1, c2, detInv, t0, t1]
  //         depths: 10   8    6    4    2   0
  emitPickFp2(ops, 4);   // copy detInv
  emitFp2Mul(ops);        // [..., c0, c1, c2, detInv, t0, r1]
  emitToAltFp2(ops);      // alt: [P, r2, r1]

  // r0 = t0 * detInv
  // Stack: [..., c0, c1, c2, detInv, t0]
  //         depths: 8    6    4    2    0
  emitRollFp2(ops, 2);   // roll detInv to top: [..., c0, c1, c2, t0, detInv]
  emitFp2Mul(ops);        // [..., c0, c1, c2, r0]
  emitToAltFp2(ops);      // alt: [P, r2, r1, r0]

  // Drop original c0, c1, c2 (6 slots)
  emitDropFp2(ops);       // drop c2
  emitDropFp2(ops);       // drop c1
  emitDropFp2(ops);       // drop c0

  // Restore results: LIFO pops r0 first, then r1, then r2
  emitFromAltFp2(ops);   // r0. alt: [P, r2, r1]
  emitFromAltFp2(ops);   // r1. alt: [P, r2]
  emitFromAltFp2(ops);   // r2. alt: [P]
  // Stack: [..., r0, r1, r2]  — correct order
}
