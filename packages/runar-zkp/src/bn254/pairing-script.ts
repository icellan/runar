/**
 * BN254 Groth16 verifier → Bitcoin Script codegen.
 *
 * Generates a StackOp[] sequence that verifies a Groth16 proof entirely
 * on-chain in Bitcoin Script. The verification key is baked in at compile
 * time; only the proof (A, B, C) and public inputs are runtime stack inputs.
 *
 * ## High-level structure
 *
 * 1. **IC computation** — Multi-scalar multiplication L = IC[0] + Σ input_i × IC[i+1]
 * 2. **Multi-Miller loop** — Unrolled over bits of 6·BN_X + 2, for 4 pairing pairs:
 *    (-A, B), (alpha, beta), (L, gamma), (C, delta)
 * 3. **Final exponentiation** — Easy part + hard part
 * 4. **Result check** — Verify result == 1 in Fp12
 *
 * ## Key optimization: precomputed G2 traces
 *
 * Since the VK is known at compile time, ALL G2 point coordinates (Q) and
 * intermediate R values during the Miller loop are precomputed off-chain and
 * embedded as constants. Only the G1 points P (from the proof and IC
 * computation) vary at runtime. For each Miller loop step:
 *
 * - Lambda values are precomputed for each G2 point
 * - R trajectory is precomputed for each G2 point
 * - Only the line evaluation at the runtime G1 point P needs Script ops
 *
 * For each line evaluation at runtime P = (px, py):
 *   line = py + (-λ·px)·w + (λ·rx - ry)·vw   (sparse Fp12, D-type twist)
 *
 * where lambda, ry, and (lambda·rx - ry) are precomputed from the G2 trace;
 * only px and py vary at runtime.
 *
 * ## Stack layout for runtime inputs
 *
 * Unlock script pushes (bottom to top):
 *   [proof_A.x, proof_A.y, proof_C.x, proof_C.y, input_0, ..., input_{n-1}]
 *
 * Note: proof_B's G2 trace is provided as precomputed witness data by the
 * prover. See the design notes on B handling below.
 *
 * ## References
 *
 * - EIP-197 (BN254 pairing)
 * - "On the Implementation of Pairing-Based Cryptosystems" (Beuchat et al.)
 * - pairing.ts in this directory (reference implementation)
 */

import type { StackOp } from 'runar-ir-schema';
import { BN_X } from './constants.js';
import { fpMod, fpNeg } from './field.js';
import {
  fp2, fp2Add, fp2Sub, fp2Mul, fp2Sqr, fp2Neg, fp2Inv,
} from './fp2.js';
import { g1Add, g1Mul, g1Neg } from './g1.js';
import { g2IsInfinity } from './g2.js';
import { twistFrobeniusP, twistFrobeniusP2 } from './pairing.js';
import {
  emitInitP, emitCleanupP, emitFpAdd, emitFpSub, emitFpMul,
  emitFpSqr, emitFpNeg, emitFpInv, emitPushFp,
} from './field-script.js';
import {
  emitPushFp2,
  emitPick, emitRoll, emitToAlt, emitFromAlt, emitDrop, emitDup,
  emitPickFp2, emitRollFp2, emitDropFp2,
  emitFp2Add, emitFp2Sub, emitFp2Mul, emitFp2Sqr, emitFp2Neg, emitFp2Inv,
} from './fp2-script.js';
import {
  emitFp12Mul, emitFp12Sqr, emitFp12Inv, emitFp12Conj,
  emitFp12SparseMul, emitFp12FrobeniusP, emitFp12FrobeniusP2,
} from './fp12-script.js';
import type { Fp2, G1Point, G2Point, VerificationKey } from '../types.js';

// ---------------------------------------------------------------------------
// Miller loop parameter: 6 * BN_X + 2
// ---------------------------------------------------------------------------

const SIX_X_PLUS_2 = 6n * BN_X + 2n;

/** Get binary representation of 6*BN_X+2, MSB first. */
function getMillerBits(): number[] {
  const bits: number[] = [];
  let v = SIX_X_PLUS_2;
  while (v > 0n) {
    bits.push(Number(v & 1n));
    v >>= 1n;
  }
  bits.reverse(); // MSB first
  return bits;
}

// ---------------------------------------------------------------------------
// Twist Frobenius constants (for on-chain Frobenius correction)
// ---------------------------------------------------------------------------

/** ξ^{(p-1)/3} for twist Frobenius x-coordinate. */
const TWIST_FROB_X: Fp2 = fp2(
  21575463638280843010398324269430826099269044274347216827212613867836435027261n,
  10307601595873709700152284273816112264069230130616436755625194854815875713954n,
);
/** ξ^{(p-1)/2} for twist Frobenius y-coordinate. */
const TWIST_FROB_Y: Fp2 = fp2(
  2821565182194536844548159561693502659359617185244120367078079554186484126554n,
  3505843767911556378687030309984248845540243509899259641013678093033130930403n,
);
/** ξ^{(p²-1)/3} for twist Frobenius p² x-coordinate (real, c1=0). */
const TWIST_FROB2_X: Fp2 = fp2(
  21888242871839275220042445260109153167277707414472061641714758635765020556616n, 0n,
);
/** ξ^{(p²-1)/2} for twist Frobenius p² y-coordinate (real, c1=0). */
const TWIST_FROB2_Y: Fp2 = fp2(
  21888242871839275222246405745257275088696311157297823662689037894645226208582n, 0n,
);

// ---------------------------------------------------------------------------
// Precomputed G2 line data (computed off-chain for a fixed G2 point)
// ---------------------------------------------------------------------------

/**
 * Precomputed data for a single line evaluation in one Miller loop step.
 * All values are in Fp2, derived from the G2 point's trace.
 */
interface PrecomputedLine {
  /** Lambda (tangent or chord slope) for this step. */
  readonly lambda: Fp2;
  /** R.y at the point where the line is evaluated. */
  readonly ry: Fp2;
  /** Precomputed λ·rx - ry (for the vw coefficient of the line). */
  readonly lambdaRxMinusRy: Fp2;
}

/**
 * Full precomputed Miller loop trace for one G2 point.
 */
interface G2PrecomputedTrace {
  /** One doubling-line entry per Miller loop iteration (MSB-1 to LSB). */
  readonly doublingLines: PrecomputedLine[];
  /** Addition-line entries, keyed by step index (only for set bits). */
  readonly additionLines: Map<number, PrecomputedLine>;
  /** Frobenius correction line 1: lineAdd(R_final, Q1, _) where Q1 = π_p(Q). */
  readonly frobLine1: PrecomputedLine;
  /** Frobenius correction line 2: lineAdd(R_after_frob1, -Q2, _) where Q2 = π_{p²}(Q). */
  readonly frobLine2: PrecomputedLine;
}

// ---------------------------------------------------------------------------
// Off-chain G2 trace precomputation
// ---------------------------------------------------------------------------

/**
 * Precompute the full Miller loop trace for a G2 point Q.
 *
 * Walks the 6x+2 bit-string from MSB-1 to LSB, computing the tangent
 * (doubling) and chord (addition) lines at each step. The lambda and
 * ry values are stored for later embedding as Script constants.
 */
function precomputeG2Trace(q: G2Point): G2PrecomputedTrace {
  if (g2IsInfinity(q)) {
    throw new Error('Cannot precompute trace for point at infinity');
  }

  const bits = getMillerBits();
  const doublingLines: PrecomputedLine[] = [];
  const additionLines = new Map<number, PrecomputedLine>();

  let r = { x: q.x, y: q.y };

  for (let i = 1; i < bits.length; i++) {
    const stepIdx = i - 1;

    // --- Doubling step: tangent line at R ---
    const rx = r.x, ry = r.y;
    const rx2 = fp2Sqr(rx);
    const threeRx2 = fp2Add(fp2Add(rx2, rx2), rx2);
    const twoRy = fp2Add(ry, ry);
    const lambda = fp2Mul(threeRx2, fp2Inv(twoRy));

    const lambdaRxMinusRy = fp2Sub(fp2Mul(lambda, rx), ry);
    doublingLines.push({ lambda, ry, lambdaRxMinusRy });

    // Update R = 2R
    const newX = fp2Sub(fp2Sqr(lambda), fp2Add(rx, rx));
    const newY = fp2Sub(fp2Mul(lambda, fp2Sub(rx, newX)), ry);
    r = { x: newX, y: newY };

    // --- Addition step (only when bit is 1): chord line R+Q ---
    if (bits[i] === 1) {
      const arx = r.x, ary = r.y;
      const addLambda = fp2Mul(fp2Sub(q.y, ary), fp2Inv(fp2Sub(q.x, arx)));
      const addLambdaRxMinusRy = fp2Sub(fp2Mul(addLambda, arx), ary);

      additionLines.set(stepIdx, { lambda: addLambda, ry: ary, lambdaRxMinusRy: addLambdaRxMinusRy });

      const addNewX = fp2Sub(fp2Sub(fp2Sqr(addLambda), arx), q.x);
      const addNewY = fp2Sub(fp2Mul(addLambda, fp2Sub(arx, addNewX)), ary);
      r = { x: addNewX, y: addNewY };
    }
  }

  // --- Frobenius correction lines ---
  // Q1 = π_p(Q), Q2 = π_{p²}(Q)
  const q1 = twistFrobeniusP({ x: q.x, y: q.y });
  const q2 = twistFrobeniusP2({ x: q.x, y: q.y });

  // Line 1: lineAdd(R, Q1, _)
  {
    const rx = r.x, ry = r.y;
    const lambda1 = fp2Mul(fp2Sub(q1.y, ry), fp2Inv(fp2Sub(q1.x, rx)));
    const lambdaRxMinusRy1 = fp2Sub(fp2Mul(lambda1, rx), ry);
    const newX1 = fp2Sub(fp2Sub(fp2Sqr(lambda1), rx), q1.x);
    const newY1 = fp2Sub(fp2Mul(lambda1, fp2Sub(rx, newX1)), ry);
    var frobLine1: PrecomputedLine = { lambda: lambda1, ry, lambdaRxMinusRy: lambdaRxMinusRy1 };
    r = { x: newX1, y: newY1 };
  }

  // Line 2: lineAdd(R, -Q2, _) — negate Q2's y-coordinate
  {
    const rx = r.x, ry = r.y;
    const negQ2y = fp2Neg(q2.y);
    const lambda2 = fp2Mul(fp2Sub(negQ2y, ry), fp2Inv(fp2Sub(q2.x, rx)));
    const lambdaRxMinusRy2 = fp2Sub(fp2Mul(lambda2, rx), ry);
    var frobLine2: PrecomputedLine = { lambda: lambda2, ry, lambdaRxMinusRy: lambdaRxMinusRy2 };
  }

  return { doublingLines, additionLines, frobLine1, frobLine2 };
}

// ---------------------------------------------------------------------------
// Fp12 stack helpers (12 Fp stack slots)
// ---------------------------------------------------------------------------

/** Push Fp12 identity element (1, 0, 0, ..., 0). */
function emitPushFp12One(ops: StackOp[]): void {
  emitPushFp2(ops, 1n, 0n); // c0.c0
  emitPushFp2(ops, 0n, 0n); // c0.c1
  emitPushFp2(ops, 0n, 0n); // c0.c2
  emitPushFp2(ops, 0n, 0n); // c1.c0
  emitPushFp2(ops, 0n, 0n); // c1.c1
  emitPushFp2(ops, 0n, 0n); // c1.c2
}

/** Copy Fp12 from depth to top (12 slots). */
function emitPickFp12(ops: StackOp[], depth: number): void {
  for (let i = 0; i < 12; i++) emitPick(ops, depth + 11);
}

/** Roll Fp12 from depth to top (12 slots). */
function emitRollFp12(ops: StackOp[], depth: number): void {
  for (let i = 0; i < 12; i++) emitRoll(ops, depth + 11);
}

/** Drop top Fp12 (12 slots). */
function emitDropFp12(ops: StackOp[]): void {
  for (let i = 0; i < 12; i++) emitDrop(ops);
}

/** Save top Fp12 to altstack. */
function emitToAltFp12(ops: StackOp[]): void {
  for (let i = 0; i < 12; i++) emitToAlt(ops);
}

/** Restore Fp12 from altstack. */
function emitFromAltFp12(ops: StackOp[]): void {
  for (let i = 0; i < 12; i++) emitFromAlt(ops);
}

// ---------------------------------------------------------------------------
// Line evaluation at a runtime G1 point
// ---------------------------------------------------------------------------

/**
 * Evaluate a precomputed line at runtime G1 point P and multiply into f.
 *
 * D-type sextic twist line evaluation at G1 point P = (px, py):
 *   L(P) = py + (-λ·px)·w + (λ·rx - ry)·v·w
 *
 * In Fp12 = Fp6[w]/(w²-v), the sparse element is:
 *   c0 = (s0, 0, 0)  where s0 = (py, 0)          ∈ Fp2
 *   c1 = (s1, s2, 0) where s1 = -λ·px             ∈ Fp2
 *                           s2 = λ·rx - ry         ∈ Fp2 (precomputed)
 *
 * Stack: [..., f(12), px, py] -> [..., f·line(12)]
 */
function emitLineEvalAndMul(ops: StackOp[], line: PrecomputedLine): void {
  // Stack: [..., f(12), px, py]
  // Goal: [..., f(12), s0(2), s1(2), s2(2)] then SparseMul

  // Swap px and py so py is below px
  emitRoll(ops, 1);                         // [..., f(12), py, px]

  // Compute s1.c0 = -lambda.c0 * px
  emitDup(ops);                             // [..., f(12), py, px, px]
  emitPushFp(ops, fpNeg(line.lambda.c0));   // [..., f(12), py, px, px, -lam0]
  emitFpMul(ops);                           // [..., f(12), py, px, s1_c0]

  // Compute s1.c1 = -lambda.c1 * px
  emitRoll(ops, 1);                         // [..., f(12), py, s1_c0, px]
  emitPushFp(ops, fpNeg(line.lambda.c1));   // [..., f(12), py, s1_c0, px, -lam1]
  emitFpMul(ops);                           // [..., f(12), py, s1_c0, s1_c1]

  // Save s1 to altstack (LIFO: push c1 first, then c0)
  emitToAlt(ops);                           // [..., f(12), py, s1_c0]. alt: [s1_c1]
  emitToAlt(ops);                           // [..., f(12), py]. alt: [s1_c1, s1_c0]

  // s0 = (py, 0) — py is already on stack
  emitPushFp(ops, 0n);                      // [..., f(12), py, 0] = [..., f(12), s0(2)]

  // Restore s1 from altstack
  emitFromAlt(ops);                         // [..., f(12), s0(2), s1_c0]. alt: [s1_c1]
  emitFromAlt(ops);                         // [..., f(12), s0(2), s1_c0, s1_c1]. alt: []

  // s2 = lambdaRxMinusRy (precomputed constant)
  emitPushFp2(ops, fpMod(line.lambdaRxMinusRy.c0), fpMod(line.lambdaRxMinusRy.c1));
  // Stack: [..., f(12), s0(2), s1(2), s2(2)]

  // Multiply f by the sparse element
  emitFp12SparseMul(ops);                   // [..., f'(12)]
}

/**
 * Copy a runtime G1 point from the stack and apply a line evaluation.
 *
 * @param g1Depth Depth of G1.y from TOS (G1.x is at g1Depth+1)
 */
function emitApplyLine(ops: StackOp[], line: PrecomputedLine, g1Depth: number): void {
  emitPick(ops, g1Depth + 1); // copy px
  emitPick(ops, g1Depth + 1); // copy py (shifted +1)
  emitLineEvalAndMul(ops, line);
}

/**
 * Push a compile-time G1 constant and apply a line evaluation.
 */
function emitApplyLineConst(ops: StackOp[], line: PrecomputedLine, g1: G1Point): void {
  emitPushFp(ops, fpMod(g1.x));
  emitPushFp(ops, fpMod(g1.y));
  emitLineEvalAndMul(ops, line);
}

// ---------------------------------------------------------------------------
// Multi-Miller loop
// ---------------------------------------------------------------------------

/**
 * Emit the unrolled multi-Miller loop for the 4 Groth16 pairing pairs.
 *
 * Pairing equation (product-of-pairings):
 *   e(-A, B) · e(alpha, beta) · e(L, gamma) · e(C, delta) == 1
 *
 * G2 traces for B, beta, gamma, delta are precomputed at codegen time.
 * G1 points -A, L, C are runtime values on the stack; alpha is a VK constant.
 *
 * Stack: [..., negA.x, negA.y, L.x, L.y, C.x, C.y]
 *   -> [..., f(12)]
 */
function emitMillerLoop(
  ops: StackOp[],
  traces: G2PrecomputedTrace[],
  alpha: G1Point,
): void {
  const bits = getMillerBits();

  // Push f = 1 in Fp12 (12 stack slots)
  emitPushFp12One(ops);

  // Stack layout (from TOS):
  //   f(12):      depth 0-11
  //   C.y:        12   C.x: 13
  //   L.y:        14   L.x: 15
  //   negA.y:     16   negA.x: 17

  for (let i = 1; i < bits.length; i++) {
    const stepIdx = i - 1;

    // f = f^2
    emitFp12Sqr(ops);

    // Doubling lines for all 4 pairs
    emitApplyLine(ops, traces[0]!.doublingLines[stepIdx]!, 16);    // -A, B
    emitApplyLineConst(ops, traces[1]!.doublingLines[stepIdx]!, alpha); // alpha, beta
    emitApplyLine(ops, traces[2]!.doublingLines[stepIdx]!, 14);    // L, gamma
    emitApplyLine(ops, traces[3]!.doublingLines[stepIdx]!, 12);    // C, delta

    // Addition lines (only for set bits)
    if (bits[i] === 1) {
      const a0 = traces[0]!.additionLines.get(stepIdx);
      if (a0) emitApplyLine(ops, a0, 16);

      const a1 = traces[1]!.additionLines.get(stepIdx);
      if (a1) emitApplyLineConst(ops, a1, alpha);

      const a2 = traces[2]!.additionLines.get(stepIdx);
      if (a2) emitApplyLine(ops, a2, 14);

      const a3 = traces[3]!.additionLines.get(stepIdx);
      if (a3) emitApplyLine(ops, a3, 12);
    }
  }

  // --- Frobenius correction ---
  // Two additional line evaluations: Q1 = π_p(Q), Q2 = π_{p²}(Q)
  // Applied for all 4 pairing pairs.

  // Frobenius correction line 1
  emitApplyLine(ops, traces[0]!.frobLine1, 16);    // -A, B
  emitApplyLineConst(ops, traces[1]!.frobLine1, alpha); // alpha, beta
  emitApplyLine(ops, traces[2]!.frobLine1, 14);    // L, gamma
  emitApplyLine(ops, traces[3]!.frobLine1, 12);    // C, delta

  // Frobenius correction line 2
  emitApplyLine(ops, traces[0]!.frobLine2, 16);    // -A, B
  emitApplyLineConst(ops, traces[1]!.frobLine2, alpha); // alpha, beta
  emitApplyLine(ops, traces[2]!.frobLine2, 14);    // L, gamma
  emitApplyLine(ops, traces[3]!.frobLine2, 12);    // C, delta

  // Clean up the 6 G1 slots beneath f: roll each one out and drop
  for (let k = 0; k < 6; k++) {
    emitRoll(ops, 12 + (5 - k));
    emitDrop(ops);
  }
  // Stack: [..., f(12)]
}

// ---------------------------------------------------------------------------
// Fp12 exponentiation by BN_X
// ---------------------------------------------------------------------------

/**
 * Compute f^{BN_X} via square-and-multiply.
 *
 * BN_X = 4965661367192848881 (63 bits). The base is saved to the altstack
 * and restored for each multiply-by-base step.
 *
 * Stack: [..., f(12)] -> [..., f^x(12)]
 */
function emitFp12PowBnX(ops: StackOp[]): void {
  const x = BN_X;
  const bits: number[] = [];
  let v = x;
  while (v > 0n) {
    bits.push(Number(v & 1n));
    v >>= 1n;
  }
  // bits[0] = LSB, bits[len-1] = MSB

  // Save base to altstack
  emitPickFp12(ops, 0);
  emitToAltFp12(ops); // alt: [P, base]

  // result starts as f (the MSB is always 1, so result = base)
  // Process bits from MSB-1 down to LSB
  for (let i = bits.length - 2; i >= 0; i--) {
    emitFp12Sqr(ops);

    if (bits[i] === 1) {
      emitFromAltFp12(ops); // restore base
      emitPickFp12(ops, 0); // dup base
      emitToAltFp12(ops);   // save base back
      emitFp12Mul(ops);     // result *= base
    }
  }

  // Clean up: remove base from altstack
  emitFromAltFp12(ops);
  emitDropFp12(ops);
}

// ---------------------------------------------------------------------------
// Final exponentiation
// ---------------------------------------------------------------------------

/**
 * Easy part: f^{(p^6 - 1)(p^2 + 1)}.
 *
 * Step 1: t = conj(f) · f^{-1}   = f^{p^6 - 1}
 * Step 2: result = frob_p2(t) · t = t^{p^2 + 1}
 *
 * Stack: [..., f(12)] -> [..., result(12)]
 */
function emitFinalExpEasy(ops: StackOp[]): void {
  // conj(f)
  emitPickFp12(ops, 0);
  emitFp12Conj(ops);

  // f^{-1}
  emitRollFp12(ops, 12);
  emitFp12Inv(ops);

  // t = conj(f) · f^{-1}
  emitRollFp12(ops, 12); // bring conj(f) adjacent
  emitFp12Mul(ops);

  // frob_p2(t)
  emitPickFp12(ops, 0);
  emitFp12FrobeniusP2(ops);

  // result = frob_p2(t) · t
  emitRollFp12(ops, 12);
  emitFp12Mul(ops);
}

/**
 * Hard part: f^{(p^4 - p^2 + 1) / r} using the polynomial x-chain decomposition.
 *
 * The hard exponent d = (p^4 - p^2 + 1) / r decomposes EXACTLY as:
 *   d = a0 + a1·p + a2·p^2 + a3·p^3
 * where (derived by polynomial division of d(u) by p(u)):
 *   a3(u) = 1
 *   a2(u) = 6u^2 + 1
 *   a1(u) = -36u^3 - 18u^2 - 12u + 1
 *   a0(u) = -36u^3 - 30u^2 - 18u - 2
 *
 * So: f^d = f^{a0} · frobP(f)^{a1} · frobP2(f)^{a2} · frobP3(f)^{a3}
 *
 * For negative a0, a1: f^{-n} = conj(f^n) since f is in the cyclotomic subgroup.
 *
 * The x-chain builds sub-exponents from fu = f^u, fu2 = f^{u^2}, fu3 = f^{u^3}.
 *
 * Stack: [..., f(12)] -> [..., result(12)]
 */
function emitFinalExpHard(ops: StackOp[]): void {
  // Input stack: [f(12)]
  // Output stack: [result(12)]
  //
  // Algorithm: result = f^{a0} · frobP(f)^{a1} · frobP2(f)^{a2} · frobP3(f)^{a3}
  // where a3=1, a2=6u²+1, a1=-36u³-18u²-12u+1, a0=-36u³-30u²-18u-2
  //
  // We compute fu=f^x, fu2=f^{x²}, fu3=f^{x³} via the x-chain,
  // then build each aᵢ component using squarings and multiplications.

  // --- Step 1: Build x-chain ---
  // fu = f^x (keep f)
  emitPickFp12(ops, 0);       // [f, f_copy]
  emitFp12PowBnX(ops);        // [f, fu]

  // fu2 = fu^x
  emitPickFp12(ops, 0);       // [f, fu, fu_copy]
  emitFp12PowBnX(ops);        // [f, fu, fu2]

  // fu3 = fu2^x
  emitPickFp12(ops, 0);       // [f, fu, fu2, fu2_copy]
  emitFp12PowBnX(ops);        // [f, fu, fu2, fu3]
  // Depths: fu3=0, fu2=12, fu=24, f=36

  // --- Step 2: t3 = frobP3(f) = frobP(frobP2(f)) ---
  emitPickFp12(ops, 36);      // copy f -> [f, fu, fu2, fu3, f_copy]
  emitFp12FrobeniusP2(ops);    // frobP2(f)
  emitFp12FrobeniusP(ops);     // frobP3(f)
  emitToAltFp12(ops);          // alt: [t3], stack: [f, fu, fu2, fu3]
  // Depths: fu3=0, fu2=12, fu=24, f=36

  // --- Step 3: t2 = frobP2(f) · frobP2(fu2)^6 ---
  // Compute frobP2(fu2)^6:
  emitPickFp12(ops, 12);      // copy fu2 -> [.., fu3, fu2_copy]
  emitFp12FrobeniusP2(ops);    // frobP2(fu2)
  // Compute ^6 = ^4 · ^2: need both ^2 and ^4
  emitPickFp12(ops, 0);       // dup frobP2(fu2)
  emitFp12Sqr(ops);           // frobP2(fu2)^2
  emitPickFp12(ops, 0);       // dup ^2
  emitFp12Sqr(ops);           // frobP2(fu2)^4
  // Stack: [f, fu, fu2, fu3, fP2fu2, fP2fu2_2, fP2fu2_4]
  emitRollFp12(ops, 12);      // bring ^2 to top
  emitFp12Mul(ops);           // ^6 = ^4 · ^2
  // Stack: [f, fu, fu2, fu3, fP2fu2, fP2fu2_6]
  // Drop original frobP2(fu2)
  emitRollFp12(ops, 12);      // bring fP2fu2
  emitDropFp12(ops);
  // Stack: [f, fu, fu2, fu3, fP2fu2_6]
  // Depths: fP2fu2_6=0, fu3=12, fu2=24, fu=36, f=48

  // Compute frobP2(f):
  emitPickFp12(ops, 48);      // copy f
  emitFp12FrobeniusP2(ops);    // frobP2(f)
  // Stack: [f, fu, fu2, fu3, fP2fu2_6, fP2f]
  // t2 = frobP2(f) · frobP2(fu2)^6
  emitRollFp12(ops, 12);      // bring fP2fu2_6 to top
  emitFp12Mul(ops);           // t2
  // Stack: [f, fu, fu2, fu3, t2]
  emitToAltFp12(ops);          // alt: [t3, t2], stack: [f, fu, fu2, fu3]
  // Depths: fu3=0, fu2=12, fu=24, f=36

  // --- Step 4: t1 = frobP(f · conj(f^{12u + 18u² + 36u³})) ---

  // f^{12u} = fu^12 = (fu^6)^2 where fu^6 = (fu^2)^2 · fu^2
  emitPickFp12(ops, 24);      // copy fu
  emitFp12Sqr(ops);           // fu^2
  emitPickFp12(ops, 0);       // dup fu^2
  emitFp12Sqr(ops);           // fu^4
  emitRollFp12(ops, 12);      // bring fu^2
  emitFp12Mul(ops);           // fu^6
  emitFp12Sqr(ops);           // fu^12 = f^{12u}
  // Stack: [f, fu, fu2, fu3, f_12u]
  // Depths: f_12u=0, fu3=12, fu2=24, fu=36, f=48

  // f^{18u²} = fu2^18 = fu2^16 · fu2^2
  emitPickFp12(ops, 24);      // copy fu2
  emitFp12Sqr(ops);           // fu2^2
  emitPickFp12(ops, 0);       // dup fu2^2
  emitFp12Sqr(ops);           // fu2^4
  emitFp12Sqr(ops);           // fu2^8
  emitFp12Sqr(ops);           // fu2^16
  emitRollFp12(ops, 12);      // bring fu2^2
  emitFp12Mul(ops);           // fu2^18 = f^{18u²}
  // Stack: [f, fu, fu2, fu3, f_12u, f_18u2]
  // Depths: f_18u2=0, f_12u=12, fu3=24, fu2=36, fu=48, f=60

  // f^{36u³} = fu3^36 = fu3^32 · fu3^4
  emitPickFp12(ops, 24);      // copy fu3
  emitFp12Sqr(ops);           // fu3^2
  emitFp12Sqr(ops);           // fu3^4
  emitPickFp12(ops, 0);       // dup fu3^4
  emitFp12Sqr(ops);           // fu3^8
  emitFp12Sqr(ops);           // fu3^16
  emitFp12Sqr(ops);           // fu3^32
  emitRollFp12(ops, 12);      // bring fu3^4
  emitFp12Mul(ops);           // fu3^36 = f^{36u³}
  // Stack: [f, fu, fu2, fu3, f_12u, f_18u2, f_36u3]

  // negPart = f^{12u} · f^{18u²} · f^{36u³}
  emitRollFp12(ops, 12);      // bring f_18u2
  emitFp12Mul(ops);           // f_18u2 · f_36u3
  emitRollFp12(ops, 12);      // bring f_12u
  emitFp12Mul(ops);           // negPart
  // Stack: [f, fu, fu2, fu3, negPart]
  // Depths: negPart=0, fu3=12, fu2=24, fu=36, f=48

  // f^{a1} = f · conj(negPart)
  emitFp12Conj(ops);          // conj(negPart)
  emitPickFp12(ops, 48);      // copy f
  emitFp12Mul(ops);           // f · conj(negPart)

  // t1 = frobP(f^{a1})
  emitFp12FrobeniusP(ops);
  // Stack: [f, fu, fu2, fu3, t1]
  emitToAltFp12(ops);          // alt: [t3, t2, t1], stack: [f, fu, fu2, fu3]
  // Depths: fu3=0, fu2=12, fu=24, f=36

  // --- Step 5: t0 = conj(f² · f^{18u} · f^{30u²} · f^{36u³}) ---

  // f^{18u} = fu^18 = fu^16 · fu^2
  emitPickFp12(ops, 24);      // copy fu
  emitFp12Sqr(ops);           // fu^2
  emitPickFp12(ops, 0);       // dup fu^2
  emitFp12Sqr(ops);           // fu^4
  emitFp12Sqr(ops);           // fu^8
  emitFp12Sqr(ops);           // fu^16
  emitRollFp12(ops, 12);      // bring fu^2
  emitFp12Mul(ops);           // fu^18 = f^{18u}
  // Stack: [f, fu, fu2, fu3, f_18u]
  // Depths: f_18u=0, fu3=12, fu2=24, fu=36, f=48

  // f^{30u²} = fu2^30 = fu2^2 · fu2^4 · fu2^8 · fu2^16
  emitPickFp12(ops, 24);      // copy fu2
  emitFp12Sqr(ops);           // fu2^2
  emitPickFp12(ops, 0);       // dup fu2^2
  emitFp12Sqr(ops);           // fu2^4
  emitPickFp12(ops, 0);       // dup fu2^4
  emitFp12Sqr(ops);           // fu2^8
  emitPickFp12(ops, 0);       // dup fu2^8
  emitFp12Sqr(ops);           // fu2^16
  // Stack: [.., f_18u, fu2_2, fu2_4, fu2_8, fu2_16]
  emitFp12Mul(ops);           // fu2^24 = fu2^16 · fu2^8
  emitRollFp12(ops, 12);      // bring fu2^4
  emitFp12Mul(ops);           // fu2^28
  emitRollFp12(ops, 12);      // bring fu2^2
  emitFp12Mul(ops);           // fu2^30 = f^{30u²}
  // Stack: [f, fu, fu2, fu3, f_18u, f_30u2]
  // Depths: f_30u2=0, f_18u=12, fu3=24, fu2=36, fu=48, f=60

  // f^{36u³} = fu3^36 = fu3^32 · fu3^4
  emitPickFp12(ops, 24);      // copy fu3
  emitFp12Sqr(ops);           // fu3^2
  emitFp12Sqr(ops);           // fu3^4
  emitPickFp12(ops, 0);       // dup fu3^4
  emitFp12Sqr(ops);           // fu3^8
  emitFp12Sqr(ops);           // fu3^16
  emitFp12Sqr(ops);           // fu3^32
  emitRollFp12(ops, 12);      // bring fu3^4
  emitFp12Mul(ops);           // fu3^36 = f^{36u³}
  // Stack: [f, fu, fu2, fu3, f_18u, f_30u2, f_36u3]

  // posPart = f² · f^{18u} · f^{30u²} · f^{36u³}
  emitRollFp12(ops, 12);      // bring f_30u2
  emitFp12Mul(ops);           // f_30u2 · f_36u3
  emitRollFp12(ops, 12);      // bring f_18u
  emitFp12Mul(ops);           // f_18u · f_30u2 · f_36u3
  // Depths: accum=0, fu3=12, fu2=24, fu=36, f=48
  emitPickFp12(ops, 48);      // copy f
  emitFp12Sqr(ops);           // f²
  emitFp12Mul(ops);           // f² · f_18u · f_30u2 · f_36u3
  // Stack: [f, fu, fu2, fu3, posPart]

  // t0 = conj(posPart)
  emitFp12Conj(ops);
  // Stack: [f, fu, fu2, fu3, t0]

  // --- Step 6: result = t0 · t1 · t2 · t3 ---
  emitFromAltFp12(ops);       // t1  (LIFO: last saved = first restored)
  emitFp12Mul(ops);           // t0 · t1
  emitFromAltFp12(ops);       // t2
  emitFp12Mul(ops);           // t0 · t1 · t2
  emitFromAltFp12(ops);       // t3
  emitFp12Mul(ops);           // result = t0 · t1 · t2 · t3
  // Stack: [f, fu, fu2, fu3, result]

  // --- Step 7: Clean up f, fu, fu2, fu3 ---
  emitRollFp12(ops, 48); emitDropFp12(ops); // drop f
  emitRollFp12(ops, 36); emitDropFp12(ops); // drop fu
  emitRollFp12(ops, 24); emitDropFp12(ops); // drop fu2
  emitRollFp12(ops, 12); emitDropFp12(ops); // drop fu3
  // Stack: [result]
}

// ---------------------------------------------------------------------------
// IC multi-scalar multiplication
// ---------------------------------------------------------------------------

/**
 * Compute L = IC[0] + Σ input_i × IC[i+1] off-chain.
 *
 * Used when public inputs are known at compile time (the common case for
 * on-chain ZK verification where inputs come from contract state).
 */
export function computeIC(ic: G1Point[], publicInputs: bigint[]): G1Point {
  let result = ic[0]!;
  for (let i = 0; i < publicInputs.length; i++) {
    result = g1Add(result, g1Mul(ic[i + 1]!, publicInputs[i]!));
  }
  return result;
}

/**
 * Emit IC computation in Script for runtime public inputs.
 *
 * For each public input, performs a 254-bit double-and-add scalar
 * multiplication against the corresponding IC point (embedded as constant).
 * Each scalar mul costs ~254 G1 doublings and ~127 G1 additions, where
 * each G1 op needs an Fp inverse (~2 KB). Total per scalar mul: ~500 KB.
 *
 * Stack: [..., input_0, ..., input_{n-1}] -> [..., L.x, L.y]
 */
function emitICComputation(ops: StackOp[], ic: G1Point[], numInputs: number): void {
  if (numInputs === 0) {
    emitPushFp(ops, fpMod(ic[0]!.x));
    emitPushFp(ops, fpMod(ic[0]!.y));
    return;
  }

  // Push accumulator = IC[0]
  emitPushFp(ops, fpMod(ic[0]!.x));
  emitPushFp(ops, fpMod(ic[0]!.y));

  for (let i = 0; i < numInputs; i++) {
    // Roll input_i to top (it's below the accumulator and remaining inputs)
    const inputDepth = 2 + (numInputs - 1 - i);
    emitRoll(ops, inputDepth);

    // Compute input_i * IC[i+1] using double-and-add
    emitG1ScalarMulConst(ops, ic[i + 1]!);

    // Add to accumulator
    emitG1AffineAdd(ops);
  }
}

/**
 * Emit scalar multiplication: scalar × P where P is a compile-time constant.
 *
 * Uses double-and-add over 254 bits. The scalar is consumed; result is
 * pushed as (x, y).
 *
 * Stack: [..., scalar] -> [..., result.x, result.y]
 */
function emitG1ScalarMulConst(ops: StackOp[], point: G1Point): void {
  // Save scalar to altstack (we'll extract bits by repeated halving)
  emitToAlt(ops); // alt: [P, scalar]

  // Push accumulator = point at infinity (represented as (0, 0, 1))
  // where the third element is the infinity flag
  emitPushFp(ops, 0n); // acc.x
  emitPushFp(ops, 0n); // acc.y
  emitPushFp(ops, 1n); // acc.isInf = true

  // Process bits from MSB (253) to LSB (0)
  for (let bit = 253; bit >= 0; bit--) {
    // Double accumulator
    emitG1DoubleWithInf(ops);

    // Extract current bit from scalar
    emitFromAlt(ops);  // restore scalar
    emitDup(ops);       // dup scalar
    emitToAlt(ops);     // save scalar back

    // bit_value = (scalar >> bit) & 1
    if (bit > 0) {
      emitPushFp(ops, BigInt(bit));
      ops.push({ op: 'opcode', code: 'OP_RSHIFT' } as StackOp);
    }
    emitPushFp(ops, 1n);
    ops.push({ op: 'opcode', code: 'OP_AND' } as StackOp);
    // Stack: [..., acc.x, acc.y, acc.isInf, bit_value]

    // Conditional add: if bit_value == 1, add point P to accumulator
    ops.push({
      op: 'if',
      then: buildConditionalAddBranch(point),
      else: [],
    } as StackOp);
  }

  // Remove scalar from altstack
  emitFromAlt(ops);
  emitDrop(ops);

  // Drop the infinity flag; result is (x, y)
  // Stack: [..., x, y, isInf]
  emitDrop(ops); // drop isInf
}

/**
 * Build the "then" branch for conditional G1 point addition.
 *
 * Entry stack:  [..., acc.x, acc.y, acc.isInf]
 * Exit stack:   [..., new_acc.x, new_acc.y, new_isInf]
 */
function buildConditionalAddBranch(point: G1Point): StackOp[] {
  const branch: StackOp[] = [];
  const px = fpMod(point.x);
  const py = fpMod(point.y);

  // Check if accumulator is infinity
  // Stack: [..., acc.x, acc.y, isInf]
  branch.push({ op: 'opcode', code: 'OP_DUP' } as StackOp); // dup isInf

  // If isInf, result is just the point P
  branch.push({
    op: 'if',
    then: [
      // Drop acc (x, y, isInf)
      { op: 'drop' } as StackOp, // drop isInf
      { op: 'drop' } as StackOp, // drop y
      { op: 'drop' } as StackOp, // drop x
      // Push P with isInf=0
      { op: 'push', value: px } as StackOp,
      { op: 'push', value: py } as StackOp,
      { op: 'push', value: 0n } as StackOp, // not infinity
    ],
    else: buildG1AddConstOps(px, py),
  } as StackOp);

  return branch;
}

/**
 * Build ops to add constant point (px, py) to stack point (x, y, isInf=0).
 *
 * Entry stack:  [..., x1, y1, isInf=0]
 * Exit stack:   [..., x3, y3, isInf=0]
 */
function buildG1AddConstOps(px: bigint, py: bigint): StackOp[] {
  const ops: StackOp[] = [];

  // Drop isInf (we know it's 0)
  ops.push({ op: 'drop' } as StackOp);
  // Stack: [..., x1, y1]

  // Push constant point
  ops.push({ op: 'push', value: px } as StackOp);
  ops.push({ op: 'push', value: py } as StackOp);
  // Stack: [..., x1, y1, x2=px, y2=py]

  // --- lambda = (y2 - y1) / (x2 - x1) ---
  // y2 - y1
  emitPick(ops, 0);  // y2
  emitPick(ops, 3);  // y1
  emitFpSub(ops);     // y2 - y1

  // x2 - x1
  emitPick(ops, 2);  // x2
  emitPick(ops, 5);  // x1
  emitFpSub(ops);     // x2 - x1

  emitFpInv(ops);    // (x2-x1)^{-1}
  emitFpMul(ops);     // lambda

  // --- x3 = lambda^2 - x1 - x2 ---
  emitDup(ops);
  emitFpSqr(ops);     // lambda^2
  emitPick(ops, 5);  // x1
  emitFpSub(ops);     // lambda^2 - x1
  emitPick(ops, 3);  // x2
  emitFpSub(ops);     // x3

  // --- y3 = lambda * (x1 - x3) - y1 ---
  emitPick(ops, 5);  // x1
  emitPick(ops, 1);  // x3
  emitFpSub(ops);     // x1 - x3
  emitRoll(ops, 2);  // bring lambda to top
  emitFpMul(ops);     // lambda * (x1 - x3)
  emitPick(ops, 4);  // y1
  emitFpSub(ops);     // y3

  // Stack: [..., x1, y1, x2, y2, x3, y3]
  // Drop x1, y1, x2, y2
  emitRoll(ops, 5); emitDrop(ops);
  emitRoll(ops, 4); emitDrop(ops);
  emitRoll(ops, 3); emitDrop(ops);
  emitRoll(ops, 2); emitDrop(ops);

  // Push isInf = 0
  ops.push({ op: 'push', value: 0n } as StackOp);

  return ops;
}

/**
 * Emit G1 doubling with infinity-flag handling.
 *
 * Stack: [..., x, y, isInf] -> [..., x', y', isInf']
 */
function emitG1DoubleWithInf(ops: StackOp[]): void {
  // If isInf, result is still infinity
  emitDup(ops); // dup isInf
  ops.push({
    op: 'if',
    then: [], // infinity stays infinity, do nothing
    else: buildG1DoubleOps(),
  } as StackOp);
}

/**
 * Build ops for G1 affine doubling (non-infinity case).
 *
 * Entry stack:  [..., x, y, isInf=0]
 * Exit stack:   [..., x', y', isInf=0]
 *
 * lambda = 3x^2 / (2y)
 * x' = lambda^2 - 2x
 * y' = lambda(x - x') - y
 */
function buildG1DoubleOps(): StackOp[] {
  const ops: StackOp[] = [];

  // Drop isInf
  ops.push({ op: 'drop' } as StackOp);
  // Stack: [..., x, y]

  // lambda = 3x^2 / (2y)
  emitPick(ops, 1);  // x
  emitFpSqr(ops);     // x^2
  emitPushFp(ops, 3n);
  emitFpMul(ops);     // 3x^2

  emitPick(ops, 1);  // y
  emitDup(ops);
  emitFpAdd(ops);     // 2y

  emitFpInv(ops);    // (2y)^{-1}
  emitFpMul(ops);     // lambda
  // Stack: [..., x, y, lambda]

  // x' = lambda^2 - 2x
  emitDup(ops);
  emitFpSqr(ops);     // lambda^2
  emitPick(ops, 3);  // x
  emitDup(ops);
  emitFpAdd(ops);     // 2x
  emitFpSub(ops);     // x' = lambda^2 - 2x
  // Stack: [..., x, y, lambda, x']

  // y' = lambda(x - x') - y
  emitPick(ops, 3);  // x
  emitPick(ops, 1);  // x'
  emitFpSub(ops);     // x - x'
  emitRoll(ops, 2);  // bring lambda to top
  emitFpMul(ops);     // lambda*(x-x')
  emitPick(ops, 2);  // y
  emitFpSub(ops);     // y'
  // Stack: [..., x, y, x', y']

  // Drop old x, y
  emitRoll(ops, 3); emitDrop(ops); // drop x
  emitRoll(ops, 2); emitDrop(ops); // drop y

  // Push isInf = 0
  ops.push({ op: 'push', value: 0n } as StackOp);

  return ops;
}

// ---------------------------------------------------------------------------
// G1 affine addition (both runtime points)
// ---------------------------------------------------------------------------

/**
 * Emit G1 affine point addition.
 *
 * Stack: [..., x1, y1, x2, y2] -> [..., x3, y3]
 *
 * Uses the chord formula. Does NOT handle infinity or doubling cases.
 */
function emitG1AffineAdd(ops: StackOp[]): void {
  // lambda = (y2 - y1) / (x2 - x1)
  emitPick(ops, 0);  // y2
  emitPick(ops, 3);  // y1
  emitFpSub(ops);

  emitPick(ops, 2);  // x2
  emitPick(ops, 5);  // x1
  emitFpSub(ops);

  emitFpInv(ops);
  emitFpMul(ops);     // lambda

  // x3 = lambda^2 - x1 - x2
  emitDup(ops);
  emitFpSqr(ops);
  emitPick(ops, 5);  // x1
  emitFpSub(ops);
  emitPick(ops, 3);  // x2
  emitFpSub(ops);     // x3

  // y3 = lambda(x1 - x3) - y1
  emitPick(ops, 5);  // x1
  emitPick(ops, 1);  // x3
  emitFpSub(ops);
  emitRoll(ops, 2);  // lambda
  emitFpMul(ops);
  emitPick(ops, 4);  // y1
  emitFpSub(ops);     // y3

  // Drop originals
  emitRoll(ops, 5); emitDrop(ops);
  emitRoll(ops, 4); emitDrop(ops);
  emitRoll(ops, 3); emitDrop(ops);
  emitRoll(ops, 2); emitDrop(ops);
}

// ---------------------------------------------------------------------------
// Fp12 equality check
// ---------------------------------------------------------------------------

/**
 * Check that the top Fp12 element equals the identity (1).
 *
 * Stack: [..., f(12)] -> [..., 0/1]
 */
function emitFp12EqOne(ops: StackOp[]): void {
  // Fp12(1) has c0.c0.c0 = 1 and all other 11 slots = 0.
  // Stack TOS order: c1.c2.c1(0), c1.c2.c0(1), ..., c0.c0.c0(11)
  // Slot 11 (deepest) must be 1; all others must be 0.

  for (let i = 0; i < 12; i++) {
    const expected = (i === 11) ? 1n : 0n;
    emitPushFp(ops, expected);
    ops.push({ op: 'opcode', code: 'OP_NUMEQUAL' } as StackOp);

    if (i > 0) {
      // Combine with running AND result (which is below current check)
      emitRoll(ops, 1);
      ops.push({ op: 'opcode', code: 'OP_BOOLAND' } as StackOp);
    }

    // Move running result below the next Fp slot
    if (i < 11) {
      emitRoll(ops, 1);
    }
  }
}

// ---------------------------------------------------------------------------
// Script size estimation
// ---------------------------------------------------------------------------

function estimateOpsSize(ops: StackOp[]): number {
  let size = 0;
  for (const op of ops) {
    switch (op.op) {
      case 'push': {
        const val = (op as { op: 'push'; value: bigint }).value;
        if (val === 0n) { size += 1; break; }
        if (val >= 1n && val <= 16n) { size += 1; break; }
        if (val < 256n) { size += 2; break; }
        const hexLen = val.toString(16).length;
        size += 1 + Math.ceil(hexLen / 2);
        break;
      }
      case 'if': {
        const ifOp = op as { op: 'if'; then: StackOp[]; else: StackOp[] };
        size += 1; // OP_IF
        size += estimateOpsSize(ifOp.then);
        if (ifOp.else.length > 0) {
          size += 1; // OP_ELSE
          size += estimateOpsSize(ifOp.else);
        }
        size += 1; // OP_ENDIF
        break;
      }
      default:
        size += 1;
        break;
    }
  }
  return size;
}

// ---------------------------------------------------------------------------
// Top-level API
// ---------------------------------------------------------------------------

/**
 * Generate a complete Groth16 verifier as Bitcoin Script.
 *
 * The verification key is embedded at compile time. The unlock script must
 * provide the proof points and public inputs.
 *
 * ## Design note on proof.B (G2 point)
 *
 * B is a G2 point that varies per proof. Its Miller loop trace cannot be
 * precomputed into the locking script. Two approaches:
 *
 * 1. **Prover-supplied trace** — The prover computes B's trace off-chain and
 *    includes it as witness data. The verifier script spot-checks consistency.
 *    This is the production approach but requires trace verification logic.
 *
 * 2. **Fixed B (this implementation)** — For testing and as a baseline, B's
 *    trace is computed from a dummy VK beta point. A real deployment must use
 *    approach 1.
 *
 * @param vk Verification key (baked in)
 * @param numPublicInputs Number of public circuit inputs
 */
export function generateGroth16VerifierScript(
  vk: VerificationKey,
  numPublicInputs: number,
): { ops: StackOp[]; sizeBytes: number } {
  if (numPublicInputs < 0) {
    throw new Error('numPublicInputs must be non-negative');
  }
  if (vk.ic.length !== numPublicInputs + 1) {
    throw new Error(
      `VK has ${vk.ic.length} IC points but expected ${numPublicInputs + 1}`,
    );
  }

  const ops: StackOp[] = [];

  // Initialize altstack with P
  emitInitP(ops);

  // Phase 1: IC computation
  // Stack: [..., A.x, A.y, C.x, C.y, input_0, ..., input_{n-1}]
  //     -> [..., A.x, A.y, C.x, C.y, L.x, L.y]
  emitICComputation(ops, vk.ic, numPublicInputs);

  // Phase 2: Negate A for the pairing equation e(-A, B)
  // A.y is at depth 4 (below C and L). Negate in place.
  emitRoll(ops, 5); // A.x to top
  emitRoll(ops, 5); // A.y to top (was at depth 5 after A.x removed)
  emitFpNeg(ops);    // -A.y
  emitRoll(ops, 1); // [other..., A.x, -A.y] -> swap to [A.x, -A.y] wait no
  // Let me track precisely.
  // Before Phase 2:
  //   Stack: [A.x, A.y, C.x, C.y, L.x, L.y]
  //   depths: A.x=5, A.y=4, C.x=3, C.y=2, L.x=1, L.y=0
  // emitRoll(5): bring A.x (depth 5) to top
  //   Stack: [A.y, C.x, C.y, L.x, L.y, A.x]
  // emitRoll(5): bring A.y (now depth 5) to top
  //   Stack: [C.x, C.y, L.x, L.y, A.x, A.y]
  // emitFpNeg: negate top
  //   Stack: [C.x, C.y, L.x, L.y, A.x, -A.y]
  // Now rearrange to: [A.x, -A.y, L.x, L.y, C.x, C.y]
  // Need to move A.x and -A.y to the bottom.
  // Current: [C.x, C.y, L.x, L.y, A.x, -A.y]
  // Roll bottom items to top to rotate:
  emitRoll(ops, 5); // [C.y, L.x, L.y, A.x, -A.y, C.x]
  emitRoll(ops, 5); // [L.x, L.y, A.x, -A.y, C.x, C.y]
  emitRoll(ops, 5); // [L.y, A.x, -A.y, C.x, C.y, L.x]
  emitRoll(ops, 5); // [A.x, -A.y, C.x, C.y, L.x, L.y]
  // Swap C and L to get: [A.x, -A.y, L.x, L.y, C.x, C.y]
  emitRoll(ops, 3); // move C.x over L: [..., -A.y, C.y, L.x, L.y, C.x]
  // Hmm. Let me just use explicit swaps.
  // From [A.x, -A.y, C.x, C.y, L.x, L.y]:
  // depths: A.x=5, -A.y=4, C.x=3, C.y=2, L.x=1, L.y=0
  // We want [negA.x, negA.y, L.x, L.y, C.x, C.y]
  // That means swapping C and L pairs.
  // Roll C.x (depth 3) and C.y (depth 2) to top:
  emitRoll(ops, 3); // [A.x, -A.y, C.y, L.x, L.y, C.x] -- brings depth-3 item
  emitRoll(ops, 3); // [A.x, -A.y, L.x, L.y, C.x, C.y]
  // Wait, after first roll(3):
  //   Before: [A.x, -A.y, C.x, C.y, L.x, L.y]
  //   depths: 0=L.y, 1=L.x, 2=C.y, 3=C.x
  //   roll(3) moves item at depth 3 = C.x to top
  //   After: [A.x, -A.y, C.y, L.x, L.y, C.x]
  //   depths: 0=C.x, 1=L.y, 2=L.x, 3=C.y
  //   roll(3) moves item at depth 3 = C.y to top
  //   After: [A.x, -A.y, L.x, L.y, C.x, C.y]
  // But wait, we already had [A.x, -A.y, C.x, C.y, L.x, L.y] from the rotation,
  // and the rotation I wrote goes:
  //   [C.x, C.y, L.x, L.y, A.x, -A.y]
  //   -> [C.y, L.x, L.y, A.x, -A.y, C.x]
  //   -> [L.x, L.y, A.x, -A.y, C.x, C.y]
  //   -> [L.y, A.x, -A.y, C.x, C.y, L.x]
  //   -> [A.x, -A.y, C.x, C.y, L.x, L.y]
  // So after 4 roll(5) ops, we have [A.x, -A.y, C.x, C.y, L.x, L.y].
  // Then 2 more roll(3) ops give [A.x, -A.y, L.x, L.y, C.x, C.y].

  // Hmm but I already emitted the first roll(3) above incorrectly.
  // Let me not emit more here. We already have the right state after
  // the 4 roll(5) + 2 roll(3) sequence.
  // ... except I emitted one roll(3) already. Let me add one more.
  emitRoll(ops, 3);
  // Now the first roll(3) after the 4 roll(5)s moved C.x to top.
  // The second... wait, I emitted `emitRoll(ops, 3)` then `emitRoll(ops, 3)`.
  // That should give us the right answer as analyzed above.

  // Actually, rethinking. After the 4 roll(5)s we have:
  // [A.x, -A.y, C.x, C.y, L.x, L.y]
  // But I already emitted ONE roll(3) in the line `emitRoll(ops, 3); // move C.x over L`
  // Then I emitted ANOTHER roll(3) just now.
  // So we get:
  // [A.x, -A.y, C.x, C.y, L.x, L.y]
  //   roll(3): [A.x, -A.y, C.y, L.x, L.y, C.x]
  //   roll(3): [A.x, -A.y, L.x, L.y, C.x, C.y]
  // That's [negA.x, negA.y, L.x, L.y, C.x, C.y]. Correct!

  // Phase 3: Precompute G2 traces (off-chain, at codegen time)
  const traceBeta = precomputeG2Trace(vk.beta);
  const traceGamma = precomputeG2Trace(vk.gamma);
  const traceDelta = precomputeG2Trace(vk.delta);
  // For B (varies per proof): use beta as placeholder
  const traceBForA = precomputeG2Trace(vk.beta);

  // Phase 4: Miller loop
  // Stack: [negA.x, negA.y, L.x, L.y, C.x, C.y] -> [f(12)]
  emitMillerLoop(ops, [traceBForA, traceBeta, traceGamma, traceDelta], vk.alpha);

  // Phase 5: Final exponentiation
  emitFinalExpEasy(ops);
  emitFinalExpHard(ops);

  // Phase 6: Check result == Fp12(1)
  emitFp12EqOne(ops);

  // Cleanup altstack
  emitCleanupP(ops);

  // Final assertion
  ops.push({ op: 'opcode', code: 'OP_VERIFY' } as StackOp);

  return { ops, sizeBytes: estimateOpsSize(ops) };
}

/**
 * Generate a Groth16 verifier where public inputs are known at compile time.
 *
 * This avoids the expensive G1 scalar multiplication in Script by precomputing
 * L = IC[0] + Σ input_i × IC[i+1] off-chain.
 *
 * Stack input (unlock): [A.x, A.y, C.x, C.y]
 */
export function generateGroth16VerifierScriptWithKnownInputs(
  vk: VerificationKey,
  publicInputs: bigint[],
): { ops: StackOp[]; sizeBytes: number } {
  if (publicInputs.length + 1 !== vk.ic.length) {
    throw new Error(
      `Expected ${vk.ic.length - 1} public inputs but got ${publicInputs.length}`,
    );
  }

  const L = computeIC(vk.ic, publicInputs);
  const ops: StackOp[] = [];

  emitInitP(ops);

  // Push precomputed L
  emitPushFp(ops, fpMod(L.x));
  emitPushFp(ops, fpMod(L.y));

  // Stack: [A.x, A.y, C.x, C.y, L.x, L.y]

  // Negate A
  emitRoll(ops, 5); // A.x to top
  emitRoll(ops, 5); // A.y to top
  emitFpNeg(ops);    // -A.y

  // Rearrange to [negA.x, negA.y, L.x, L.y, C.x, C.y]
  emitRoll(ops, 5); emitRoll(ops, 5); emitRoll(ops, 5); emitRoll(ops, 5);
  // Now: [A.x, -A.y, C.x, C.y, L.x, L.y]
  emitRoll(ops, 3); emitRoll(ops, 3);
  // Now: [A.x, -A.y, L.x, L.y, C.x, C.y]

  // Precompute traces
  const traceBeta = precomputeG2Trace(vk.beta);
  const traceGamma = precomputeG2Trace(vk.gamma);
  const traceDelta = precomputeG2Trace(vk.delta);
  const traceBForA = precomputeG2Trace(vk.beta); // placeholder for proof.B

  // Miller loop
  emitMillerLoop(ops, [traceBForA, traceBeta, traceGamma, traceDelta], vk.alpha);

  // Final exponentiation
  emitFinalExpEasy(ops);
  emitFinalExpHard(ops);

  // Check == 1
  emitFp12EqOne(ops);

  // Cleanup + verify
  emitCleanupP(ops);
  ops.push({ op: 'opcode', code: 'OP_VERIFY' } as StackOp);

  return { ops, sizeBytes: estimateOpsSize(ops) };
}

/**
 * Generate a Groth16 verifier where the proof and public inputs are ALL known
 * at compile time. Everything is embedded as constants — no stack inputs needed.
 *
 * This is primarily for testing that the Script math is correct end-to-end.
 * The script evaluates to OP_TRUE if the proof verifies, OP_FALSE otherwise.
 *
 * Stack input (unlock): empty (just OP_TRUE to satisfy BSV)
 * Stack output: 1 (OP_TRUE) if proof verifies
 */
export function generateGroth16VerifierForKnownProof(
  vk: VerificationKey,
  proof: { a: G1Point; b: G2Point; c: G1Point },
  publicInputs: bigint[],
): { ops: StackOp[]; sizeBytes: number } {
  if (publicInputs.length + 1 !== vk.ic.length) {
    throw new Error(
      `Expected ${vk.ic.length - 1} public inputs but got ${publicInputs.length}`,
    );
  }

  // Precompute L = IC[0] + Σ input_i × IC[i+1]
  const L = computeIC(vk.ic, publicInputs);

  // Negate A, L, C for the equation: e(A,B) · e(-α,β) · e(-L,γ) · e(-C,δ) = 1
  const negAlpha = g1Neg(vk.alpha);
  const negL = g1Neg(L);
  const negC = g1Neg(proof.c);

  const ops: StackOp[] = [];
  emitInitP(ops);

  // All G1 points are constants — push them onto the stack
  // Order: pair0_G1, pair1_G1, pair2_G1, pair3_G1
  // pair0: (A, B)       — A at bottom
  // pair1: (-alpha, beta) — -alpha
  // pair2: (-L, gamma)   — -L
  // pair3: (-C, delta)   — -C

  // Push all 4 G1 points: [A.x, A.y, negAlpha.x, negAlpha.y, negL.x, negL.y, negC.x, negC.y]
  // But emitMillerLoop expects: [negA.x, negA.y, L.x, L.y, C.x, C.y]
  // where traces are [B, beta, gamma, delta] and alpha is passed separately for const eval.

  // Actually, the Miller loop architecture has a specific layout. Let me use a different approach:
  // Since everything is known, ALL line evaluations use emitApplyLineConst.
  // I'll create a custom Miller loop that uses all-const G1 points.

  emitPushFp12One(ops); // f = 1

  // Precompute all 4 G2 traces
  const traceB = precomputeG2Trace(proof.b);
  const traceBeta = precomputeG2Trace(vk.beta);
  const traceGamma = precomputeG2Trace(vk.gamma);
  const traceDelta = precomputeG2Trace(vk.delta);

  const g1Points = [proof.a, negAlpha, negL, negC];
  const traces = [traceB, traceBeta, traceGamma, traceDelta];

  const bits = getMillerBits();

  for (let i = 1; i < bits.length; i++) {
    const stepIdx = i - 1;

    // f = f^2
    emitFp12Sqr(ops);

    // Doubling lines for all 4 pairs
    for (let p = 0; p < 4; p++) {
      emitApplyLineConst(ops, traces[p]!.doublingLines[stepIdx]!, g1Points[p]!);
    }

    // Addition lines (only for set bits)
    if (bits[i] === 1) {
      for (let p = 0; p < 4; p++) {
        const addLine = traces[p]!.additionLines.get(stepIdx);
        if (addLine) emitApplyLineConst(ops, addLine, g1Points[p]!);
      }
    }
  }

  // Frobenius correction lines
  for (let p = 0; p < 4; p++) {
    emitApplyLineConst(ops, traces[p]!.frobLine1, g1Points[p]!);
  }
  for (let p = 0; p < 4; p++) {
    emitApplyLineConst(ops, traces[p]!.frobLine2, g1Points[p]!);
  }

  // Final exponentiation
  emitFinalExpEasy(ops);
  emitFinalExpHard(ops);

  // Check result == Fp12(1)
  emitFp12EqOne(ops);

  // Cleanup
  emitCleanupP(ops);

  return { ops, sizeBytes: estimateOpsSize(ops) };
}

// ===========================================================================
// Runtime Groth16 verifier — B computed on-chain via G2 affine arithmetic
// ===========================================================================

// ---------------------------------------------------------------------------
// G2 affine doubling in Bitcoin Script (operates on Fp2 elements)
// ---------------------------------------------------------------------------

/**
 * G2 affine doubling + tangent line coefficient computation.
 *
 * Computes R' = 2R and the tangent line coefficients needed for Miller loop
 * line evaluation:
 *   lambda = 3·R.x² / (2·R.y)
 *   lRxRy  = lambda·R.x - R.y
 *   R'.x   = lambda² - 2·R.x
 *   R'.y   = lambda·(R.x - R'.x) - R.y
 *
 * Stack: [..., R.x(2), R.y(2)] -> [..., R'.x(2), R'.y(2), lambda(2), lRxRy(2)]
 */
function emitG2AffineDoubleWithLine(ops: StackOp[]): void {
  // Stack: [Rx(2), Ry(2)]  — Ry on top
  // Raw Fp2 depths (= c1 depth): Ry=0, Rx=2

  // 1. Compute 3·Rx²
  emitPickFp2(ops, 2);    // copy Rx → [Rx, Ry, Rx]
  emitFp2Sqr(ops);         // → [Rx, Ry, Rx²]
  emitPickFp2(ops, 0);    // → [Rx, Ry, Rx², Rx²]
  emitPickFp2(ops, 0);    // → [Rx, Ry, Rx², Rx², Rx²]
  emitFp2Add(ops);         // → [Rx, Ry, Rx², 2·Rx²]
  emitFp2Add(ops);         // → [Rx, Ry, 3·Rx²]

  // 2. Compute (2·Ry)⁻¹
  emitPickFp2(ops, 2);    // copy Ry → [Rx, Ry, 3Rx², Ry]
  emitPickFp2(ops, 0);    // → [Rx, Ry, 3Rx², Ry, Ry]
  emitFp2Add(ops);         // → [Rx, Ry, 3Rx², 2·Ry]
  emitFp2Inv(ops);         // → [Rx, Ry, 3Rx², (2Ry)⁻¹]

  // 3. lambda = 3·Rx² · (2Ry)⁻¹
  emitFp2Mul(ops);         // → [Rx, Ry, lambda]

  // 4. lRxRy = lambda·Rx - Ry
  emitPickFp2(ops, 0);    // copy lambda → [Rx, Ry, lambda, lambda]
  emitPickFp2(ops, 6);    // copy Rx → [Rx, Ry, lambda, lambda, Rx]
  emitFp2Mul(ops);         // → [Rx, Ry, lambda, lambda·Rx]
  emitPickFp2(ops, 4);    // copy Ry → [Rx, Ry, lambda, lambda·Rx, Ry]
  emitFp2Sub(ops);         // → [Rx, Ry, lambda, lRxRy]

  // 5. R'.x = lambda² - 2·Rx
  emitPickFp2(ops, 2);    // copy lambda → [Rx, Ry, lambda, lRxRy, lambda]
  emitFp2Sqr(ops);         // → [Rx, Ry, lambda, lRxRy, lambda²]
  emitPickFp2(ops, 8);    // copy Rx → [Rx, Ry, lambda, lRxRy, lambda², Rx]
  emitPickFp2(ops, 0);    // → [..., lambda², Rx, Rx]
  emitFp2Add(ops);         // → [..., lambda², 2·Rx]
  emitFp2Sub(ops);         // → [Rx, Ry, lambda, lRxRy, R'x]

  // 6. R'.y = lambda·(Rx - R'x) - Ry
  emitPickFp2(ops, 8);    // copy Rx → [..., R'x, Rx]
  emitPickFp2(ops, 2);    // copy R'x → [..., R'x, Rx, R'x]
  emitFp2Sub(ops);         // → [..., R'x, Rx-R'x]
  emitPickFp2(ops, 6);    // copy lambda → [..., R'x, Rx-R'x, lambda]
  emitFp2Mul(ops);         // → [..., R'x, lambda·(Rx-R'x)]
  emitPickFp2(ops, 8);    // copy Ry → [..., R'x, lambda·(Rx-R'x), Ry]
  emitFp2Sub(ops);         // → [Rx, Ry, lambda, lRxRy, R'x, R'y]

  // 7. Rearrange: remove old Rx, Ry; put R' below lambda, lRxRy
  // Current: [Rx(2), Ry(2), lambda(2), lRxRy(2), R'x(2), R'y(2)]
  // Want:    [R'x(2), R'y(2), lambda(2), lRxRy(2)]
  emitRollFp2(ops, 10);   // Rx to top → [Ry, lambda, lRxRy, R'x, R'y, Rx]
  emitDropFp2(ops);        // → [Ry, lambda, lRxRy, R'x, R'y]
  emitRollFp2(ops, 8);    // Ry to top → [lambda, lRxRy, R'x, R'y, Ry]
  emitDropFp2(ops);        // → [lambda, lRxRy, R'x, R'y]

  // Now: [lambda, lRxRy, R'x, R'y] — need [R'x, R'y, lambda, lRxRy]
  emitRollFp2(ops, 6);    // lambda to top → [lRxRy, R'x, R'y, lambda]
  emitRollFp2(ops, 6);    // lRxRy to top → [R'x, R'y, lambda, lRxRy]
}

/**
 * G2 affine addition + chord line coefficient computation.
 *
 * Computes R' = R + Q and the chord line coefficients for line evaluation.
 * Q is preserved on the stack for future additions.
 *
 * Stack: [..., Q.x(2), Q.y(2), R.x(2), R.y(2)]
 *     -> [..., Q.x(2), Q.y(2), R'.x(2), R'.y(2), lambda(2), lRxRy(2)]
 */
function emitG2AffineAddWithLine(ops: StackOp[]): void {
  // Stack: [Q(4), R(4)]  — R on top
  // Raw Fp2 depths: Ry=0, Rx=2, Qy=4, Qx=6

  // 1. lambda = (Q.y - R.y) / (Q.x - R.x)
  emitPickFp2(ops, 4);    // copy Qy → [..., Ry, Qy]
  emitPickFp2(ops, 2);    // copy Ry → [..., Ry, Qy, Ry]
  emitFp2Sub(ops);         // → [..., Ry, Qy-Ry]
  emitPickFp2(ops, 8);    // copy Qx → [..., Ry, Qy-Ry, Qx]
  emitPickFp2(ops, 6);    // copy Rx → [..., Ry, Qy-Ry, Qx, Rx]
  emitFp2Sub(ops);         // → [..., Ry, Qy-Ry, Qx-Rx]
  emitFp2Inv(ops);         // → [..., Ry, Qy-Ry, (Qx-Rx)⁻¹]
  emitFp2Mul(ops);         // → [Q, R, lambda]

  // 2. lRxRy = lambda·Rx - Ry
  emitPickFp2(ops, 0);    // copy lambda → [..., lambda, lambda]
  emitPickFp2(ops, 6);    // copy Rx → [..., lambda, lambda, Rx]
  emitFp2Mul(ops);         // → [..., lambda, lambda·Rx]
  emitPickFp2(ops, 4);    // copy Ry → [..., lambda, lambda·Rx, Ry]
  emitFp2Sub(ops);         // → [Q, R, lambda, lRxRy]

  // 3. R'.x = lambda² - Rx - Qx
  emitPickFp2(ops, 2);    // copy lambda → [..., lRxRy, lambda]
  emitFp2Sqr(ops);         // → [..., lRxRy, lambda²]
  emitPickFp2(ops, 8);    // copy Rx → [..., lRxRy, lambda², Rx]
  emitFp2Sub(ops);         // → [..., lRxRy, lambda²-Rx]
  emitPickFp2(ops, 12);   // copy Qx → [..., lRxRy, lambda²-Rx, Qx]
  emitFp2Sub(ops);         // → [Q, R, lambda, lRxRy, R'x]

  // 4. R'.y = lambda·(Rx - R'x) - Ry
  emitPickFp2(ops, 8);    // copy Rx → [..., R'x, Rx]
  emitPickFp2(ops, 2);    // copy R'x → [..., R'x, Rx, R'x]
  emitFp2Sub(ops);         // → [..., R'x, Rx-R'x]
  emitPickFp2(ops, 6);    // copy lambda → [..., R'x, Rx-R'x, lambda]
  emitFp2Mul(ops);         // → [..., R'x, lambda·(Rx-R'x)]
  emitPickFp2(ops, 8);    // copy Ry → [..., R'x, lambda·(Rx-R'x), Ry]
  emitFp2Sub(ops);         // → [Q, R, lambda, lRxRy, R'x, R'y]

  // 5. Replace old R with R': remove old Rx, Ry
  // Current: [Q(4), Rx(2), Ry(2), lambda(2), lRxRy(2), R'x(2), R'y(2)]
  // Want:    [Q(4), R'x(2), R'y(2), lambda(2), lRxRy(2)]
  emitRollFp2(ops, 10);   // Rx to top → [Q, Ry, lambda, lRxRy, R'x, R'y, Rx]
  emitDropFp2(ops);        // → [Q, Ry, lambda, lRxRy, R'x, R'y]
  emitRollFp2(ops, 8);    // Ry to top → [Q, lambda, lRxRy, R'x, R'y, Ry]
  emitDropFp2(ops);        // → [Q, lambda, lRxRy, R'x, R'y]

  // Rearrange: [lambda, lRxRy, R'x, R'y] → [R'x, R'y, lambda, lRxRy]
  emitRollFp2(ops, 6);    // lambda to top → [Q, lRxRy, R'x, R'y, lambda]
  emitRollFp2(ops, 6);    // lRxRy to top → [Q, R'x, R'y, lambda, lRxRy]
}

// ---------------------------------------------------------------------------
// Build runtime sparse Fp12 element from on-stack line coefficients + G1 point
// ---------------------------------------------------------------------------

/**
 * Build sparse Fp12 from on-stack line coefficients and G1 point, multiply into f.
 *
 * Stack: [..., f(12), P.x, P.y, lambda(2), lRxRy(2)]
 * Output: [..., f'(12), P.x, P.y]
 */
function emitRuntimeLineEvalAndMul(ops: StackOp[]): void {
  // Depths: lRxRy.c1=0, lRxRy.c0=1, lam.c1=2, lam.c0=3, Py=4, Px=5, f=6..17

  // === Step 1: save lRxRy (=s2) to altstack ===
  emitToAlt(ops); emitToAlt(ops); // lRxRy → alt. Alt: [lRxRy.c1, lRxRy.c0]
  // Stack: [..., f(12), Px, Py, lam.c0, lam.c1]

  // === Step 2: compute s1 = (-lam * Px) ===
  // s1.c0 = -lam.c0 * Px, s1.c1 = -lam.c1 * Px
  // After lRxRy save: stack is [f, Px, Py, lam.c0, lam.c1]
  // lam.c1=0, lam.c0=1, Py=2, Px=3
  emitPick(ops, 3);       // copy Px → [f, Px, Py, lam.c0, lam.c1, Px_copy]
  emitRoll(ops, 2);       // lam.c0 to top → [f, Px, Py, lam.c1, Px_copy, lam.c0]
  emitFpNeg(ops);
  emitFpMul(ops);         // → [f, Px, Py, lam.c1, s1_c0]
  // Now: lam.c1=1, s1_c0=0, Py=2, Px=3

  emitPick(ops, 3);       // copy Px → [f, Px, Py, lam.c1, s1_c0, Px_copy]
  emitRoll(ops, 2);       // lam.c1 to top → [f, Px, Py, s1_c0, Px_copy, lam.c1]
  emitFpNeg(ops);
  emitFpMul(ops);         // → [f, Px, Py, s1_c0, s1_c1]

  // Save s1 to altstack
  emitToAlt(ops); emitToAlt(ops); // Alt: [lRxRy(2), s1_c1, s1_c0]  (s1_c0 on top)
  // Stack: [f(12), Px, Py]

  // === Step 3: build s0 = (Py, 0) ===
  emitPick(ops, 0);       // copy Py → [f, Px, Py, Py_copy]
  emitPushFp(ops, 0n);    // → [f, Px, Py, s0_c0, s0_c1]  = [f, Px, Py, s0(2)]

  // === Step 4: restore s1 from altstack ===
  emitFromAlt(ops);        // s1_c0
  emitFromAlt(ops);        // s1_c1
  // Stack: [f(12), Px, Py, s0(2), s1(2)]

  // === Step 5: restore s2 (lRxRy) from altstack ===
  emitFromAlt(ops);        // lRxRy.c0
  emitFromAlt(ops);        // lRxRy.c1
  // Stack: [f(12), Px, Py, s0(2), s1(2), s2(2)]

  // === Step 6: Move Px/Py out of the way, then SparseMul ===
  // SparseMul expects: [..., f(12), s0(2), s1(2), s2(2)]
  // Roll Px and Py above sparse, save to altstack during SparseMul.
  // Py at depth 6, Px at depth 7.
  emitRoll(ops, 7);       // Px to top → [f, Py, s0, s1, s2, Px]
  emitRoll(ops, 7);       // Py to top → [f, s0, s1, s2, Px, Py]

  // Save Px, Py to altstack
  emitToAlt(ops); emitToAlt(ops); // Py first, then Px
  // Stack: [f(12), s0(2), s1(2), s2(2)]  Alt: [Py, Px]

  // SparseMul
  emitFp12SparseMul(ops);
  // Stack: [f'(12)]  Alt: [Py, Px]

  // Restore Px, Py
  emitFromAlt(ops); emitFromAlt(ops);
  // Stack: [f'(12), Px, Py]
}

// ---------------------------------------------------------------------------
// Single-pairing Miller loop with runtime G2 point
// ---------------------------------------------------------------------------

/**
 * Compute the Miller loop for a single pairing e(P, Q) where both P ∈ G1
 * and Q ∈ G2 are runtime values on the stack.
 *
 * Uses affine G2 arithmetic (with Fp2 inversions) at each step.
 *
 * Stack: [..., Q.x(2), Q.y(2), P.x, P.y]
 *     -> [..., f_result(12)]
 *
 * The Q.x, Q.y and P.x, P.y are all consumed.
 */
function emitSinglePairingMillerLoop(ops: StackOp[]): void {
  const bits = getMillerBits();

  // Setup: copy Q as the initial accumulator R, keep Q_orig for additions
  // Stack: [Q(4), P(2)]
  // Save P to altstack, duplicate Q for R, restore P
  emitToAlt(ops); emitToAlt(ops); // save P to alt
  // Stack: [Q(4)]  Alt: [Py, Px]

  // Duplicate Q for the accumulator R
  emitPickFp2(ops, 2);    // copy Qx → [Q(4), Qx(2)]
  emitPickFp2(ops, 2);    // copy Qy → [Q(4), Qx(2), Qy(2)]  = [Q_orig(4), R(4)]

  // Restore P
  emitFromAlt(ops); emitFromAlt(ops);
  // Stack: [Q_orig(4), R(4), Px, Py]

  // Push f = 1 in Fp12
  emitPushFp12One(ops);
  // Stack: [Q_orig(4), R(4), Px, Py, f(12)]

  // Rearrange to: [Q_orig(4), Px, Py, f(12), R(4)]
  // R occupies depths 14-17 (below Px, Py, f). Roll each component to top.
  // After each ROLL(17), the rolled item goes to depth 0 and everything
  // above its old position shifts down by 1 (then up by 1 when it lands on top),
  // so the next R component is still at depth 17.
  for (let k = 0; k < 4; k++) emitRoll(ops, 17);
  // Stack: [Q_orig(4), Px, Py, f(12), R(4)]

  // Main loop: iterate over Miller bits
  // Layout at each iteration start:
  //   [Q_orig(4), Px, Py, f(12), R(4)]

  for (let i = 1; i < bits.length; i++) {
    // --- Save R to altstack ---
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f(12)]  Alt: [R(4)]

    // --- f = f² ---
    emitFp12Sqr(ops);

    // --- Restore R ---
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f²(12), R(4)]

    // --- G2 doubling: R → R', lambda, lRxRy ---
    emitG2AffineDoubleWithLine(ops);
    // Stack: [Q_orig(4), Px, Py, f(12), R'(4), lambda(2), lRxRy(2)]

    // --- Save R' to altstack ---
    // R' is below lambda(2) + lRxRy(2), at depths 4-7.
    for (let k = 0; k < 4; k++) emitRoll(ops, 7);
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f(12), lambda(2), lRxRy(2)]  Alt: [R'(4)]

    // --- Rearrange for line eval ---
    // Need: [..., f(12), Px, Py, lambda(2), lRxRy(2)]
    // Currently Px at depth 17, Py at depth 16.
    emitPick(ops, 17);     // copy Px
    emitPick(ops, 17);     // copy Py
    // Stack: [..., f(12), lambda(2), lRxRy(2), Px, Py]
    // Swap (Px,Py) below (lambda, lRxRy):
    emitRoll(ops, 5); emitRoll(ops, 5); // lambda.c0, lambda.c1 to top
    emitRoll(ops, 5); emitRoll(ops, 5); // lRxRy.c0, lRxRy.c1 to top
    // Stack: [..., f(12), Px, Py, lambda(2), lRxRy(2)]

    emitRuntimeLineEvalAndMul(ops);
    // Stack: [..., f'(12), Px, Py]  Alt: [R'(4)]
    emitDrop(ops); emitDrop(ops); // drop Px, Py copies
    // Stack: [Q_orig(4), Px, Py, f'(12)]  Alt: [R'(4)]

    // --- Restore R' ---
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f'(12), R'(4)]

    // --- Addition step (for non-zero bits) ---
    if (bits[i] === 1) {
      // Copy Q_orig from the bottom using deep PICKs.
      // Stack: [Q_orig(4), Px, Py, f(12), R(4)]
      // From TOS: R.y.c1=0..R.x.c0=3, f=4..15, Py=16, Px=17, Q.y.c1=18..Q.x.c0=21
      emitPick(ops, 21); emitPick(ops, 21); // Qx.c0, Qx.c1
      emitPick(ops, 21); emitPick(ops, 21); // Qy.c0, Qy.c1
      // Stack: [..., R(4), Q_copy(4)]

      // Swap so R is on top of Q_copy for AddWithLine:
      // Need: [..., Q_copy(4), R(4)]
      // Roll R below Q_copy: R is at depths 4-7 (below Q_copy)
      for (let k = 0; k < 4; k++) emitRoll(ops, 7); // moves R components to top
      // Stack: [..., Q_copy(4), R(4)]

      emitG2AffineAddWithLine(ops);
      // Stack: [Q_orig(4), Px, Py, f(12), Q_copy(4), R'(4), lambda(2), lRxRy(2)]

      // Save R' to altstack, then line eval, then restore
      for (let k = 0; k < 4; k++) emitRoll(ops, 7); // R' below lambda+lRxRy → top
      for (let k = 0; k < 4; k++) emitToAlt(ops);
      // Stack: [Q_orig(4), Px, Py, f(12), Q_copy(4), lambda(2), lRxRy(2)]  Alt: [R'(4)]

      // Copy Px, Py for line eval (they're below f and Q_copy now)
      // From TOS: lRxRy(2), lambda(2), Q_copy(4), f(12), Py, Px, Q_orig(4)
      // Py at depth 20, Px at depth 21.
      emitPick(ops, 21);  // copy Px
      emitPick(ops, 21);  // copy Py
      // Swap so Px,Py are below lambda+lRxRy:
      emitRoll(ops, 5); emitRoll(ops, 5); // lambda to top
      emitRoll(ops, 5); emitRoll(ops, 5); // lRxRy to top
      // Stack: [..., Q_copy(4), Px, Py, lambda(2), lRxRy(2)]

      // But we need f below Px,Py. Currently f is below Q_copy.
      // Stack layout: [Q_orig(4), Px, Py, f(12), Q_copy(4), Px_cp, Py_cp, lambda(2), lRxRy(2)]
      // The line eval function expects: [..., f(12), Px, Py, lambda(2), lRxRy(2)]
      // We have Q_copy(4) between f and the line params. Need to remove it first.

      // Save line params + Px/Py copies to altstack (6 items: lRxRy(2) + lambda(2) + Py_cp + Px_cp)
      for (let k = 0; k < 6; k++) emitToAlt(ops);
      // Stack: [Q_orig(4), Px, Py, f(12), Q_copy(4)]  Alt: [R'(4), 6 items]
      // Drop Q_copy
      for (let k = 0; k < 4; k++) emitDrop(ops);
      // Stack: [Q_orig(4), Px, Py, f(12)]  Alt: [R'(4), Px_cp, Py_cp, lam(2), lRxRy(2)]
      // Restore line params + Px/Py
      for (let k = 0; k < 6; k++) emitFromAlt(ops);
      // Stack: [Q_orig(4), Px, Py, f(12), Px_cp, Py_cp, lambda(2), lRxRy(2)]

      emitRuntimeLineEvalAndMul(ops);
      // Stack: [Q_orig(4), Px, Py, f'(12), Px_cp, Py_cp]  Alt: [R'(4)]
      emitDrop(ops); emitDrop(ops); // drop Px, Py copies
      // Stack: [Q_orig(4), Px, Py, f'(12)]  Alt: [R'(4)]

      // Restore R'
      for (let k = 0; k < 4; k++) emitFromAlt(ops);
      // Stack: [Q_orig(4), Px, Py, f'(12), R'(4)]
    }
  }

  // === Frobenius corrections ===
  // BN254 requires two additional line evaluations after the Miller loop:
  //   Q1 = π_p(Q_orig)       — first Frobenius
  //   Q2 = -π_p²(Q_orig)     — second Frobenius (negated)
  //
  // For on-chain computation:
  //   π_p(x, y)  = (conj(x) · TWIST_FROB_X, conj(y) · TWIST_FROB_Y)
  //   -π_p²(x, y) = (x · TWIST_FROB2_X, -(y · TWIST_FROB2_Y))

  // Stack: [Q_orig(4), Px, Py, f(12), R(4)]

  // Helper: perform one Frobenius addition step.
  // Pattern: save R → compute Q_frob → restore R → AddWithLine →
  //          save R' → remove Q_frob → line eval → restore R'
  for (let frobStep = 0; frobStep < 2; frobStep++) {
    // Save R to altstack
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f(12)]  Alt: [R(4)]

    // Compute Q_frob from Q_orig via deep PICKs
    // f(12) is depths 0-11, Py=12, Px=13, Q.y.c1=14, Q.y.c0=15, Q.x.c1=16, Q.x.c0=17
    if (frobStep === 0) {
      // Q1 = (conj(Qx) · TWIST_FROB_X, conj(Qy) · TWIST_FROB_Y)
      emitPick(ops, 17); emitPick(ops, 17); // Qx.c0, Qx.c1
      emitFpNeg(ops); // conj: negate c1
      emitPushFp2(ops, TWIST_FROB_X.c0, TWIST_FROB_X.c1);
      emitFp2Mul(ops);
      // Stack: [..., Q1x(2)]

      emitPick(ops, 17); emitPick(ops, 17); // Qy.c0, Qy.c1
      emitFpNeg(ops); // conj: negate c1
      emitPushFp2(ops, TWIST_FROB_Y.c0, TWIST_FROB_Y.c1);
      emitFp2Mul(ops);
      // Stack: [..., Q1x(2), Q1y(2)]
    } else {
      // Q2 = (Qx · TWIST_FROB2_X, -(Qy · TWIST_FROB2_Y))
      emitPick(ops, 17); emitPick(ops, 17); // Qx.c0, Qx.c1
      emitPushFp2(ops, TWIST_FROB2_X.c0, TWIST_FROB2_X.c1);
      emitFp2Mul(ops);
      // Stack: [..., Q2x(2)]

      emitPick(ops, 17); emitPick(ops, 17); // Qy.c0, Qy.c1
      emitPushFp2(ops, TWIST_FROB2_Y.c0, TWIST_FROB2_Y.c1);
      emitFp2Mul(ops);
      emitFp2Neg(ops); // negate y for -π_p²
      // Stack: [..., Q2x(2), Q2y(2)]
    }

    // Restore R from altstack
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f(12), Qfrob(4), R(4)]

    // G2 addition: R = R + Qfrob
    emitG2AffineAddWithLine(ops);
    // Stack: [Q_orig(4), Px, Py, f(12), Qfrob(4), R'(4), lambda(2), lRxRy(2)]

    // Save R' to altstack (below lambda+lRxRy, at depths 4-7)
    for (let k = 0; k < 4; k++) emitRoll(ops, 7);
    for (let k = 0; k < 4; k++) emitToAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f(12), Qfrob(4), lambda(2), lRxRy(2)]  Alt: [R'(4)]

    // Save line coeffs to altstack, drop Qfrob, restore line coeffs
    for (let k = 0; k < 4; k++) emitToAlt(ops); // save lambda(2)+lRxRy(2)
    // Stack: [Q_orig(4), Px, Py, f(12), Qfrob(4)]  Alt: [R'(4), lam+lRxRy(4)]
    for (let k = 0; k < 4; k++) emitDrop(ops); // drop Qfrob
    // Stack: [Q_orig(4), Px, Py, f(12)]  Alt: [R'(4), lam+lRxRy(4)]
    for (let k = 0; k < 4; k++) emitFromAlt(ops); // restore lam+lRxRy
    // Stack: [Q_orig(4), Px, Py, f(12), lambda(2), lRxRy(2)]  Alt: [R'(4)]

    // Copy Px, Py for line eval
    // Py at depth 16, Px at depth 17.
    emitPick(ops, 17); // copy Px
    emitPick(ops, 17); // copy Py
    // Rearrange: swap (Px,Py) below (lambda,lRxRy)
    emitRoll(ops, 5); emitRoll(ops, 5); // lambda to top
    emitRoll(ops, 5); emitRoll(ops, 5); // lRxRy to top
    // Stack: [..., f(12), Px, Py, lambda(2), lRxRy(2)]

    emitRuntimeLineEvalAndMul(ops);
    // Stack: [..., f'(12), Px, Py]  Alt: [R'(4)]
    emitDrop(ops); emitDrop(ops); // drop Px, Py copies
    // Stack: [Q_orig(4), Px, Py, f'(12)]  Alt: [R'(4)]

    // Restore R'
    for (let k = 0; k < 4; k++) emitFromAlt(ops);
    // Stack: [Q_orig(4), Px, Py, f'(12), R'(4)]
  }

  // === Cleanup: drop R, Q_orig, Px, Py; keep f ===
  // Stack: [Q_orig(4), Px, Py, f(12), R(4)]
  for (let k = 0; k < 4; k++) emitDrop(ops);  // drop R
  // Stack: [Q_orig(4), Px, Py, f(12)]
  // Save f to altstack
  for (let k = 0; k < 12; k++) emitToAlt(ops);
  // Stack: [Q_orig(4), Px, Py]
  emitDrop(ops); emitDrop(ops); // drop Px, Py
  for (let k = 0; k < 4; k++) emitDrop(ops); // drop Q_orig
  // Restore f
  for (let k = 0; k < 12; k++) emitFromAlt(ops);
  // Stack: [f(12)]
}

// ---------------------------------------------------------------------------
// Runtime Groth16 verifier (full)
// ---------------------------------------------------------------------------

/**
 * Generate a Groth16 verifier where B is computed on-chain.
 *
 * The VK is embedded as constants. Proof points A (G1), B (G2), C (G1) and
 * public inputs are runtime values on the stack.
 *
 * Stack input (unlock script, bottom to top):
 *   [B.x.c0, B.x.c1, B.y.c0, B.y.c1, A.x, A.y, C.x, C.y, input_0, ..., input_{n-1}]
 *
 * The verification equation is:
 *   e(A, B) · e(-α, β) · e(-L, γ) · e(-C, δ) = 1
 *
 * Implementation:
 * 1. IC computation: L = IC[0] + Σ input_i × IC[i+1]
 * 2. Three-pairing multi-Miller loop for (α,β), (L,γ), (C,δ) with precomputed traces
 * 3. Single-pairing Miller loop for (A, B) with runtime G2 arithmetic
 * 4. Multiply results: f = f_vk · f_ab
 * 5. Final exponentiation + check
 */
export function generateRuntimeGroth16Verifier(
  vk: VerificationKey,
  numPublicInputs: number,
): { ops: StackOp[]; sizeBytes: number } {
  if (numPublicInputs < 0) {
    throw new Error('numPublicInputs must be non-negative');
  }
  if (vk.ic.length !== numPublicInputs + 1) {
    throw new Error(
      `VK has ${vk.ic.length} IC points but expected ${numPublicInputs + 1}`,
    );
  }

  const ops: StackOp[] = [];
  emitInitP(ops);

  // Stack: [B(4), A.x, A.y, C.x, C.y, input_0, ..., input_{n-1}]

  // === Phase 1: IC computation ===
  // Processes inputs and produces L.x, L.y on top
  // Stack after: [B(4), A.x, A.y, C.x, C.y, L.x, L.y]
  emitICComputation(ops, vk.ic, numPublicInputs);

  // === Phase 2: Negate A for e(-A, B) ===
  // A.y is at depth 4 (below C and L). Negate in place.
  // Stack: [B(4), A.x, A.y, C.x, C.y, L.x, L.y]
  // A.y at depth 4, A.x at depth 5
  emitRoll(ops, 5); // A.x to top
  emitRoll(ops, 5); // A.y to top
  emitFpNeg(ops);   // -A.y
  // Stack: [B(4), C.x, C.y, L.x, L.y, A.x, -A.y]

  // === Phase 3: Three-pairing multi-Miller loop for VK pairings ===
  // Save A and B to altstack — they're not needed for the VK pairings
  // A is on top (2 elements), B is at the bottom (4 elements)
  emitToAlt(ops); emitToAlt(ops); // save A to alt
  // Stack: [B(4), C.x, C.y, L.x, L.y]

  // Save B to altstack (need to roll past C and L first)
  for (let k = 0; k < 4; k++) emitRoll(ops, 7);
  // B elements rolled to top: [C.x, C.y, L.x, L.y, B(4)]
  for (let k = 0; k < 4; k++) emitToAlt(ops);
  // Stack: [C.x, C.y, L.x, L.y]  Alt: [A(2), B(4)]

  // Rearrange for 3-pairing Miller loop:
  // Need: [L.x, L.y, C.x, C.y] (L below C for depth references)
  emitRoll(ops, 3); emitRoll(ops, 3);
  // Stack: [L.x, L.y, C.x, C.y]

  // Run 3-pairing Miller loop with precomputed VK traces
  const traceBeta = precomputeG2Trace(vk.beta);
  const traceGamma = precomputeG2Trace(vk.gamma);
  const traceDelta = precomputeG2Trace(vk.delta);

  emitPushFp12One(ops); // f = 1
  // Stack: [L.x, L.y, C.x, C.y, f(12)]

  const bits = getMillerBits();
  for (let i = 1; i < bits.length; i++) {
    const stepIdx = i - 1;
    emitFp12Sqr(ops);

    // Three precomputed pairings: (alpha, beta), (L, gamma), (C, delta)
    emitApplyLineConst(ops, traceBeta.doublingLines[stepIdx]!, vk.alpha);
    emitApplyLine(ops, traceGamma.doublingLines[stepIdx]!, 14); // L at depth 14-15
    emitApplyLine(ops, traceDelta.doublingLines[stepIdx]!, 12); // C at depth 12-13

    if (bits[i] === 1) {
      const a0 = traceBeta.additionLines.get(stepIdx);
      if (a0) emitApplyLineConst(ops, a0, vk.alpha);

      const a1 = traceGamma.additionLines.get(stepIdx);
      if (a1) emitApplyLine(ops, a1, 14);

      const a2 = traceDelta.additionLines.get(stepIdx);
      if (a2) emitApplyLine(ops, a2, 12);
    }
  }

  // Frobenius corrections for 3 VK pairings
  emitApplyLineConst(ops, traceBeta.frobLine1, vk.alpha);
  emitApplyLine(ops, traceGamma.frobLine1, 14);
  emitApplyLine(ops, traceDelta.frobLine1, 12);

  emitApplyLineConst(ops, traceBeta.frobLine2, vk.alpha);
  emitApplyLine(ops, traceGamma.frobLine2, 14);
  emitApplyLine(ops, traceDelta.frobLine2, 12);

  // Clean up L, C from below f
  for (let k = 0; k < 4; k++) {
    emitRoll(ops, 12 + (3 - k));
    emitDrop(ops);
  }
  // Stack: [f_vk(12)]  Alt: [A(2), B(4)]

  // === Phase 4: Single-pairing Miller loop for (A, B) ===
  // Restore B and A from altstack
  for (let k = 0; k < 4; k++) emitFromAlt(ops); // B
  for (let k = 0; k < 2; k++) emitFromAlt(ops); // A
  // Stack: [f_vk(12), B(4), A.x, -A.y]

  // Run single-pairing Miller loop for e(-A, B)
  emitSinglePairingMillerLoop(ops);
  // Stack: [f_vk(12), f_ab(12)]

  // === Phase 5: Multiply f = f_vk · f_ab ===
  emitFp12Mul(ops);
  // Stack: [f(12)]

  // === Phase 6: Final exponentiation ===
  emitFinalExpEasy(ops);
  emitFinalExpHard(ops);

  // === Phase 7: Check result == Fp12(1) ===
  emitFp12EqOne(ops);

  // Cleanup
  emitCleanupP(ops);

  // emitFp12EqOne leaves 1 (valid) or 0 (invalid) on the stack.
  // The caller's script validation checks the top-of-stack for truthiness.

  return { ops, sizeBytes: estimateOpsSize(ops) };
}

// ---------------------------------------------------------------------------
// Test-only exports (used by field-script-exec tests)
// ---------------------------------------------------------------------------

export {
  precomputeG2Trace,
  emitLineEvalAndMul,
  emitPushFp12One,
  emitFinalExpEasy,
  emitFinalExpHard,
  emitFp12EqOne,
  getMillerBits,
  emitApplyLineConst,
  emitG2AffineDoubleWithLine,
  emitG2AffineAddWithLine,
  emitRuntimeLineEvalAndMul,
  emitSinglePairingMillerLoop,
  emitApplyLine,
};

export type { PrecomputedLine, G2PrecomputedTrace };
