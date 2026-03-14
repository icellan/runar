/**
 * BN254 optimal Ate pairing.
 *
 * Computes the pairing e: G1 × G2 → GT (where GT ⊂ Fp12).
 * Used for Groth16 verification: e(A,B) = e(α,β) · e(L,γ) · e(C,δ).
 *
 * Implementation follows the standard Miller loop + final exponentiation
 * approach for BN curves.
 */

import { BN_X } from './constants.js';
import { fpMod, fpNeg } from './field.js';
import {
  fp2, fp2Add, fp2Sub, fp2Mul, fp2Sqr, fp2Neg, fp2Inv, fp2Eq, fp2Conj,
  FP2_ZERO, FP2_ONE, fp2MulScalar,
} from './fp2.js';
import { g1IsInfinity } from './g1.js';
import { g2IsInfinity } from './g2.js';
import type { Fp2, Fp6, Fp12, G1Point, G2Point } from '../types.js';

// ---------------------------------------------------------------------------
// Fp6 = Fp2[v] / (v^3 - ξ) where ξ = (9 + u)
// ---------------------------------------------------------------------------

const XI: Fp2 = fp2(9n, 1n); // non-residue for Fp6

const FP6_ZERO: Fp6 = { c0: FP2_ZERO, c1: FP2_ZERO, c2: FP2_ZERO };
const FP6_ONE: Fp6 = { c0: FP2_ONE, c1: FP2_ZERO, c2: FP2_ZERO };

function fp6Add(a: Fp6, b: Fp6): Fp6 {
  return { c0: fp2Add(a.c0, b.c0), c1: fp2Add(a.c1, b.c1), c2: fp2Add(a.c2, b.c2) };
}

function fp6Sub(a: Fp6, b: Fp6): Fp6 {
  return { c0: fp2Sub(a.c0, b.c0), c1: fp2Sub(a.c1, b.c1), c2: fp2Sub(a.c2, b.c2) };
}

function fp6MulByXi(a: Fp2): Fp2 {
  return fp2Mul(a, XI);
}

function fp6Mul(a: Fp6, b: Fp6): Fp6 {
  const t0 = fp2Mul(a.c0, b.c0);
  const t1 = fp2Mul(a.c1, b.c1);
  const t2 = fp2Mul(a.c2, b.c2);

  return {
    c0: fp2Add(t0, fp6MulByXi(fp2Sub(fp2Mul(fp2Add(a.c1, a.c2), fp2Add(b.c1, b.c2)), fp2Add(t1, t2)))),
    c1: fp2Add(fp2Sub(fp2Mul(fp2Add(a.c0, a.c1), fp2Add(b.c0, b.c1)), fp2Add(t0, t1)), fp6MulByXi(t2)),
    c2: fp2Add(fp2Sub(fp2Mul(fp2Add(a.c0, a.c2), fp2Add(b.c0, b.c2)), fp2Add(t0, t2)), t1),
  };
}

function fp6Sqr(a: Fp6): Fp6 {
  return fp6Mul(a, a); // can be optimized but correctness first
}

function fp6Neg(a: Fp6): Fp6 {
  return { c0: fp2Neg(a.c0), c1: fp2Neg(a.c1), c2: fp2Neg(a.c2) };
}

function fp6Inv(a: Fp6): Fp6 {
  const c0s = fp2Sqr(a.c0);
  const c1s = fp2Sqr(a.c1);
  const c2s = fp2Sqr(a.c2);

  const t0 = fp2Sub(c0s, fp6MulByXi(fp2Mul(a.c1, a.c2)));
  const t1 = fp2Sub(fp6MulByXi(c2s), fp2Mul(a.c0, a.c1));
  const t2 = fp2Sub(c1s, fp2Mul(a.c0, a.c2));

  const det = fp2Add(
    fp2Mul(a.c0, t0),
    fp6MulByXi(fp2Add(fp2Mul(a.c2, t1), fp2Mul(a.c1, t2))),
  );
  const detInv = fp2Inv(det);

  return {
    c0: fp2Mul(t0, detInv),
    c1: fp2Mul(t1, detInv),
    c2: fp2Mul(t2, detInv),
  };
}

// ---------------------------------------------------------------------------
// Fp12 = Fp6[w] / (w^2 - v)
// ---------------------------------------------------------------------------

const FP12_ONE: Fp12 = { c0: FP6_ONE, c1: FP6_ZERO };

function fp12Mul(a: Fp12, b: Fp12): Fp12 {
  const t0 = fp6Mul(a.c0, b.c0);
  const t1 = fp6Mul(a.c1, b.c1);
  // c0 = t0 + t1*v (where v = w^2 enters via the modular reduction)
  // In Fp6, multiplying by v is: {c0: xi*c2, c1: c0, c2: c1}
  const t1v: Fp6 = { c0: fp6MulByXi(t1.c2), c1: t1.c0, c2: t1.c1 };
  return {
    c0: fp6Add(t0, t1v),
    c1: fp6Sub(fp6Sub(fp6Mul(fp6Add(a.c0, a.c1), fp6Add(b.c0, b.c1)), t0), t1),
  };
}

function fp12Sqr(a: Fp12): Fp12 {
  return fp12Mul(a, a);
}

function fp12Inv(a: Fp12): Fp12 {
  const c0s = fp6Sqr(a.c0);
  const c1s = fp6Sqr(a.c1);
  // v * c1^2 where multiplying Fp6 by v: {c0: xi*c2, c1: c0, c2: c1}
  const c1sv: Fp6 = { c0: fp6MulByXi(c1s.c2), c1: c1s.c0, c2: c1s.c1 };
  const det = fp6Sub(c0s, c1sv);
  const detInv = fp6Inv(det);
  return {
    c0: fp6Mul(a.c0, detInv),
    c1: fp6Neg(fp6Mul(a.c1, detInv)),
  };
}

function fp12Conj(a: Fp12): Fp12 {
  return { c0: a.c0, c1: fp6Neg(a.c1) };
}

// ---------------------------------------------------------------------------
// Miller loop (optimal Ate)
// ---------------------------------------------------------------------------

function lineDouble(r: { x: Fp2; y: Fp2 }, p: G1Point): { coeff: Fp12; newR: { x: Fp2; y: Fp2 } } {
  const rx = r.x, ry = r.y;
  const px = fpMod(p.x), py = fpMod(p.y);

  // λ = 3*rx^2 / (2*ry) on the twist curve E'
  const rx2 = fp2Sqr(rx);
  const threeRx2 = fp2Add(fp2Add(rx2, rx2), rx2);
  const twoRy = fp2Add(ry, ry);
  const lambda = fp2Mul(threeRx2, fp2Inv(twoRy));

  // new R on twist curve
  const newX = fp2Sub(fp2Sqr(lambda), fp2Add(rx, rx));
  const newY = fp2Sub(fp2Mul(lambda, fp2Sub(rx, newX)), ry);

  // Line evaluation at P through the D-type sextic twist.
  // Twist: ψ(x',y') = (x'·v, y'·v·w) where v = w², v³ = ξ.
  // The line L(P) = py + (-λ·px)·w + (λ·rx - ry)·v·w
  // In Fp12 = Fp6[w]/(w²-v):
  //   c0 (Fp6 constant part): (py, 0, 0)
  //   c1 (Fp6 ·w part):       (-λ·px, λ·rx - ry, 0)
  const c0: Fp6 = {
    c0: fp2(py, 0n),
    c1: FP2_ZERO,
    c2: FP2_ZERO,
  };
  const c1: Fp6 = {
    c0: fp2MulScalar(lambda, fpNeg(px)),
    c1: fp2Sub(fp2Mul(lambda, rx), ry),
    c2: FP2_ZERO,
  };
  const coeff: Fp12 = { c0, c1 };

  return { coeff, newR: { x: newX, y: newY } };
}

function lineAdd(r: { x: Fp2; y: Fp2 }, q: { x: Fp2; y: Fp2 }, p: G1Point): { coeff: Fp12; newR: { x: Fp2; y: Fp2 } } {
  const rx = r.x, ry = r.y;
  const qx = q.x, qy = q.y;
  const px = fpMod(p.x), py = fpMod(p.y);

  const lambda = fp2Mul(fp2Sub(qy, ry), fp2Inv(fp2Sub(qx, rx)));
  const newX = fp2Sub(fp2Sub(fp2Sqr(lambda), rx), qx);
  const newY = fp2Sub(fp2Mul(lambda, fp2Sub(rx, newX)), ry);

  const c0: Fp6 = {
    c0: fp2(py, 0n),
    c1: FP2_ZERO,
    c2: FP2_ZERO,
  };
  const c1: Fp6 = {
    c0: fp2MulScalar(lambda, fpNeg(px)),
    c1: fp2Sub(fp2Mul(lambda, rx), ry),
    c2: FP2_ZERO,
  };
  const coeff: Fp12 = { c0, c1 };

  return { coeff, newR: { x: newX, y: newY } };
}

// ---------------------------------------------------------------------------
// Frobenius constants (needed by twist Frobenius and final exponentiation)
// ---------------------------------------------------------------------------

/**
 * Frobenius p coefficients in component order: [1, v, v², w, vw, v²w].
 * For basis element v^a · w^b, the multiplier is ξ^{(2a+b)(p-1)/6}.
 * Computed as: ξ = 9+u, exponent = (2a+b)·(p-1)/6.
 */
const FROB_P_COEFFS: Fp2[] = [
  fp2(1n, 0n), // 1: ξ^0
  fp2(  // v: ξ^{2(p-1)/6}
    21575463638280843010398324269430826099269044274347216827212613867836435027261n,
    10307601595873709700152284273816112264069230130616436755625194854815875713954n,
  ),
  fp2(  // v²: ξ^{4(p-1)/6}
    2581911344467009335267311115468803099551665605076196740867805258568234346338n,
    19937756971775647987995932169929341994314640652964949448313374472400716661030n,
  ),
  fp2(  // w: ξ^{(p-1)/6}
    8376118865763821496583973867626364092589906065868298776909617916018768340080n,
    16469823323077808223889137241176536799009286646108169935659301613961712198316n,
  ),
  fp2(  // vw: ξ^{3(p-1)/6}
    2821565182194536844548159561693502659359617185244120367078079554186484126554n,
    3505843767911556378687030309984248845540243509899259641013678093033130930403n,
  ),
  fp2(  // v²w: ξ^{5(p-1)/6}
    685108087231508774477564247770172212460312782337200605669322048753928464687n,
    8447204650696766136447902020341177575205426561248465145919723016860428151883n,
  ),
];

/** Frobenius p² coefficients in component order (same basis permutation). */
const FROB_P2_COEFFS: Fp2[] = [
  fp2(1n, 0n), // 1
  fp2(21888242871839275220042445260109153167277707414472061641714758635765020556616n, 0n), // v
  fp2(2203960485148121921418603742825762020974279258880205651966n, 0n), // v²
  fp2(21888242871839275220042445260109153167277707414472061641714758635765020556617n, 0n), // w
  fp2(21888242871839275222246405745257275088696311157297823662689037894645226208582n, 0n), // vw
  fp2(2203960485148121921418603742825762020974279258880205651967n, 0n), // v²w
];

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
/** ξ^{(p²-1)/3} for twist Frobenius p² x-coordinate. */
const TWIST_FROB2_X: Fp2 = fp2(
  21888242871839275220042445260109153167277707414472061641714758635765020556616n, 0n,
);
/** ξ^{(p²-1)/2} for twist Frobenius p² y-coordinate. */
const TWIST_FROB2_Y: Fp2 = fp2(
  21888242871839275222246405745257275088696311157297823662689037894645226208582n, 0n,
);

/**
 * Frobenius endomorphism on G2 twist points.
 * π_p(x', y') = (conj(x') · ξ^{(p-1)/3}, conj(y') · ξ^{(p-1)/2})
 * where the constants come from the Frobenius coefficients.
 */
function twistFrobeniusP(q: { x: Fp2; y: Fp2 }): { x: Fp2; y: Fp2 } {
  return {
    x: fp2Mul(fp2Conj(q.x), TWIST_FROB_X),
    y: fp2Mul(fp2Conj(q.y), TWIST_FROB_Y),
  };
}

/**
 * Frobenius p^2 on G2 twist points.
 * π_{p²}(x', y') = (x' · ξ^{(p²-1)/3}, y' · ξ^{(p²-1)/2})
 * No conjugation needed since applying Frobenius twice returns to Fp2.
 */
function twistFrobeniusP2(q: { x: Fp2; y: Fp2 }): { x: Fp2; y: Fp2 } {
  return {
    x: fp2Mul(q.x, TWIST_FROB2_X),
    y: fp2Mul(q.y, TWIST_FROB2_Y),
  };
}

function millerLoop(p: G1Point, q: G2Point): Fp12 {
  if (g1IsInfinity(p) || g2IsInfinity(q)) return FP12_ONE;

  let f = FP12_ONE;
  let r = { x: q.x, y: q.y };

  // Binary representation of 6*BN_X + 2
  const sixXPlus2 = 6n * BN_X + 2n;
  const bits: number[] = [];
  let v = sixXPlus2;
  while (v > 0n) {
    bits.push(Number(v & 1n));
    v >>= 1n;
  }

  // Miller loop: iterate bits from MSB to LSB (skip the top bit)
  for (let i = bits.length - 2; i >= 0; i--) {
    // Doubling step
    const dbl = lineDouble(r, p);
    f = fp12Mul(fp12Sqr(f), dbl.coeff);
    r = dbl.newR;

    if (bits[i] === 1) {
      // Addition step
      const add = lineAdd(r, { x: q.x, y: q.y }, p);
      f = fp12Mul(f, add.coeff);
      r = add.newR;
    }
  }

  // Frobenius correction for BN254 optimal Ate pairing:
  // Q1 = π_p(Q), Q2 = π_{p²}(Q)
  const q1 = twistFrobeniusP({ x: q.x, y: q.y });
  const q2 = twistFrobeniusP2({ x: q.x, y: q.y });

  // Line evaluation with Q1
  const add1 = lineAdd(r, q1, p);
  f = fp12Mul(f, add1.coeff);
  r = add1.newR;

  // Line evaluation with -Q2 (negate y-coordinate)
  const add2 = lineAdd(r, { x: q2.x, y: fp2Neg(q2.y) }, p);
  f = fp12Mul(f, add2.coeff);

  return f;
}

/** Miller loop without Frobenius correction (for testing). */
function millerLoopRaw(p: G1Point, q: G2Point): Fp12 {
  if (g1IsInfinity(p) || g2IsInfinity(q)) return FP12_ONE;

  let f = FP12_ONE;
  let r = { x: q.x, y: q.y };

  const sixXPlus2 = 6n * BN_X + 2n;
  const bits: number[] = [];
  let v = sixXPlus2;
  while (v > 0n) {
    bits.push(Number(v & 1n));
    v >>= 1n;
  }

  for (let i = bits.length - 2; i >= 0; i--) {
    const dbl = lineDouble(r, p);
    f = fp12Mul(fp12Sqr(f), dbl.coeff);
    r = dbl.newR;

    if (bits[i] === 1) {
      const add = lineAdd(r, { x: q.x, y: q.y }, p);
      f = fp12Mul(f, add.coeff);
      r = add.newR;
    }
  }
  return f;
}

// ---------------------------------------------------------------------------
// Final exponentiation
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Frobenius endomorphisms (off-chain)
// ---------------------------------------------------------------------------

/**
 * Frobenius p-th power: f^p.
 * Each Fp2 component gets conjugated then multiplied by a precomputed constant.
 */
function fp12FrobP(f: Fp12): Fp12 {
  const comps = [f.c0.c0, f.c0.c1, f.c0.c2, f.c1.c0, f.c1.c1, f.c1.c2];
  const mapped = comps.map((c, i) => {
    const conj = fp2Conj(c);
    const g = FROB_P_COEFFS[i]!;
    return g.c0 === 1n && g.c1 === 0n ? conj : fp2Mul(conj, g);
  });
  return {
    c0: { c0: mapped[0]!, c1: mapped[1]!, c2: mapped[2]! },
    c1: { c0: mapped[3]!, c1: mapped[4]!, c2: mapped[5]! },
  };
}

/** Frobenius p^2: f^{p^2}. All constants are real; no conjugation needed. */
function fp12FrobP2(f: Fp12): Fp12 {
  const comps = [f.c0.c0, f.c0.c1, f.c0.c2, f.c1.c0, f.c1.c1, f.c1.c2];
  const mapped = comps.map((c, i) => {
    const g = FROB_P2_COEFFS[i]!;
    return g.c0 === 1n && g.c1 === 0n ? c : fp2MulScalar(c, g.c0);
  });
  return {
    c0: { c0: mapped[0]!, c1: mapped[1]!, c2: mapped[2]! },
    c1: { c0: mapped[3]!, c1: mapped[4]!, c2: mapped[5]! },
  };
}

/** Frobenius p^3: f^{p^3} = frobP(frobP2(f)). */
function fp12FrobP3(f: Fp12): Fp12 {
  return fp12FrobP(fp12FrobP2(f));
}

// ---------------------------------------------------------------------------
// Cyclotomic squaring (for unitary elements after easy part)
// ---------------------------------------------------------------------------

/** Exponentiate by BN_X using binary method (x = BN_X). */
function fp12ExpByX(f: Fp12): Fp12 {
  let result = FP12_ONE;
  let base = f;
  let x = BN_X;
  while (x > 0n) {
    if (x & 1n) result = fp12Mul(result, base);
    base = fp12Sqr(base);
    x >>= 1n;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Final exponentiation
// ---------------------------------------------------------------------------

/**
 * Hard part of final exponentiation using x-chain decomposition.
 *
 * The hard exponent d = (p^4 - p^2 + 1) / r decomposes as:
 *   d = a0 + a1·p + a2·p^2 + a3·p^3
 * where (derived via polynomial division of d(u) by p(u)):
 *   a3 = 1
 *   a2 = 6u^2 + 1
 *   a1 = -36u^3 - 18u^2 - 12u + 1
 *   a0 = -36u^3 - 30u^2 - 18u - 2
 *
 * So: f^d = f^{a0} · frobP(f)^{a1} · frobP2(f)^{a2} · frobP3(f)^{a3}
 *
 * For negative exponents, use conjugation: f^{-n} = conj(f)^n (cyclotomic subgroup).
 *
 * x-chain to compute the sub-exponents from f^u, f^{u^2}, f^{u^3}:
 *   fu = f^u,  fu2 = fu^u = f^{u^2},  fu3 = fu2^u = f^{u^3}
 *
 *   a0 = -36u^3 - 30u^2 - 18u - 2 = -(2 + 18u + 30u^2 + 36u^3)
 *      = -(2·(1 + 3u) + 6u^2·(5 + 6u))
 *   a1 = 1 - 12u - 18u^2 - 36u^3 = 1 - 6u·(2 + 3u + 6u^2)
 *   a2 = 1 + 6u^2
 *   a3 = 1
 *
 * To minimize Fp12 exponentiations, we build the exponents from fu, fu2, fu3
 * using multiplications and squarings only.
 */
function finalExpHardXChain(f: Fp12): Fp12 {
  const fu = fp12ExpByX(f);          // f^u
  const fu2 = fp12ExpByX(fu);        // f^{u^2}
  const fu3 = fp12ExpByX(fu2);       // f^{u^3}

  // a3-component: frobP3(f)^1 = frobP3(f)
  const t3 = fp12FrobP3(f);

  // a2-component: frobP2(f)^{6u^2 + 1}
  // 6u^2 = 6 * fu2 in exponent. But we need f^{6u^2} not fu2^6...
  // Actually: frobP2(f)^{6u^2+1} = frobP2(f) · frobP2(f^{u^2})^6
  // = frobP2(f) · frobP2(fu2)^6
  // where ^6 = squaring + mul: x^6 = (x^2)^2 · x^2 = x^2 · (x^2)^2
  const fp2_fu2 = fp12FrobP2(fu2);
  const fp2_fu2_sq = fp12Sqr(fp2_fu2);               // frobP2(fu2)^2
  const fp2_fu2_4 = fp12Sqr(fp2_fu2_sq);              // frobP2(fu2)^4
  const fp2_fu2_6 = fp12Mul(fp2_fu2_4, fp2_fu2_sq);   // frobP2(fu2)^6
  const t2 = fp12Mul(fp12FrobP2(f), fp2_fu2_6);       // frobP2(f)^{6u^2+1}

  // a1-component: frobP(f)^{-36u^3 - 18u^2 - 12u + 1}
  // Since a1 = 1 - 12u - 18u^2 - 36u^3, and the negative part is large:
  // |a1| part: 12u + 18u^2 + 36u^3 = 6u(2 + 3u + 6u^2)
  // = 6u · (2 + 3u(1 + 2u))
  //
  // Build in exponent-of-f land:
  // f^{6u} = fu^6
  const fu_sq = fp12Sqr(fu);                          // fu^2
  const fu_4 = fp12Sqr(fu_sq);                        // fu^4
  const fu_6 = fp12Mul(fu_4, fu_sq);                  // fu^6 = f^{6u}

  // f^{6u^2} = fu2^6
  const fu2_sq = fp12Sqr(fu2);
  const fu2_4 = fp12Sqr(fu2_sq);
  const fu2_6 = fp12Mul(fu2_4, fu2_sq);               // f^{6u^2}

  // f^{6u^3} = fu3^6
  const fu3_sq = fp12Sqr(fu3);
  const fu3_4 = fp12Sqr(fu3_sq);
  const fu3_6 = fp12Mul(fu3_4, fu3_sq);               // f^{6u^3}

  // 12u = 2·6u, 18u^2 = 3·6u^2, 36u^3 = 6·6u^3
  const f_12u = fp12Sqr(fu_6);                        // f^{12u}
  const f_18u2 = fp12Mul(fu2_6, fp12Sqr(fu2_6));      // f^{6u^2} · f^{12u^2} = f^{18u^2}
  // Wait, fp12Sqr(fu2_6) = f^{12u^2}. fu2_6 * fp12Sqr(fu2_6) = f^{6u^2 + 12u^2} = f^{18u^2}. Yes.
  const f_36u3 = fp12Sqr(fp12Mul(fu3_6, fp12Sqr(fu3_6)));
  // fu3_6 = f^{6u^3}, fp12Sqr(fu3_6) = f^{12u^3}, fu3_6 * that = f^{18u^3}
  // sqr of that = f^{36u^3}. Yes.

  // negPart = f^{12u + 18u^2 + 36u^3}
  const negPart = fp12Mul(fp12Mul(f_12u, f_18u2), f_36u3);

  // a1 = 1 - negPart (in exponent), so frobP(f)^{a1} = frobP(f) · frobP(conj(negPart))
  // = frobP(f) · conj(frobP(negPart))... no.
  // Actually: frobP(f)^{a1} = frobP(f^{a1}) = frobP(f · conj(negPart))
  // because f^{a1} = f^{1-neg} = f · f^{-neg} = f · conj(f^{neg}) = f · conj(negPart)
  const f_a1 = fp12Mul(f, fp12Conj(negPart));
  const t1 = fp12FrobP(f_a1);

  // a0-component: f^{a0} where a0 = -(2 + 18u + 30u^2 + 36u^3)
  // = -(2 + 18u + 30u^2 + 36u^3)
  // Build:
  // f^2 just square f
  // f^{18u} = f_12u * fu_6 = f^{12u+6u} = f^{18u}
  const f_18u = fp12Mul(f_12u, fu_6);
  // f^{30u^2} = f^{18u^2} · f^{12u^2} = f_18u2 · fp12Sqr(fu2_6)
  const f_30u2 = fp12Mul(f_18u2, fp12Sqr(fu2_6));     // f^{18u^2 + 12u^2} = f^{30u^2}

  const posPart0 = fp12Mul(fp12Mul(fp12Sqr(f), f_18u), fp12Mul(f_30u2, f_36u3));
  // f^{2 + 18u + 30u^2 + 36u^3}
  const t0 = fp12Conj(posPart0);                       // f^{a0} = conjugate since a0 is negative

  // Final result: t0 · t1 · t2 · t3
  return fp12Mul(fp12Mul(t0, t1), fp12Mul(t2, t3));
}

function finalExponentiation(f: Fp12): Fp12 {
  // ---- Easy part: f^{(p^6 - 1)(p^2 + 1)} ----
  const f1 = fp12Mul(fp12Conj(f), fp12Inv(f));
  const f2 = fp12Mul(fp12FrobP2(f1), f1);

  // ---- Hard part: f2^{(p^4 - p^2 + 1) / r} via x-chain ----
  return finalExpHardXChain(f2);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute the optimal Ate pairing e(P, Q) on BN254.
 *
 * Returns an element of GT ⊂ Fp12. The result is only meaningful
 * for comparison (checking if two pairings are equal), not as an
 * absolute value.
 */
export function pairing(p: G1Point, q: G2Point): Fp12 {
  const f = millerLoop(p, q);
  return finalExponentiation(f);
}

/**
 * Check the Groth16 pairing equation:
 *   e(A, B) == e(alpha, beta) * e(L, gamma) * e(C, delta)
 *
 * This is equivalent to checking:
 *   e(A, B) * e(-L, gamma) * e(-C, delta) == e(alpha, beta)
 *
 * Or more efficiently using the product-of-pairings check:
 *   e(A, B) * e(alpha_neg, beta) * e(L_neg, gamma) * e(C_neg, delta) == 1
 */
export function checkPairingProduct(
  pairs: Array<{ g1: G1Point; g2: G2Point }>,
): boolean {
  // Compute product of Miller loops, then single final exponentiation
  let f = FP12_ONE;
  for (const { g1, g2 } of pairs) {
    if (!g1IsInfinity(g1) && !g2IsInfinity(g2)) {
      f = fp12Mul(f, millerLoop(g1, g2));
    }
  }
  const result = finalExponentiation(f);
  // Check if result == 1 in Fp12
  return fp12IsOne(result);
}

function fp12IsOne(a: Fp12): boolean {
  return fp2Eq(a.c0.c0, FP2_ONE) &&
    fp2Eq(a.c0.c1, FP2_ZERO) &&
    fp2Eq(a.c0.c2, FP2_ZERO) &&
    fp2Eq(a.c1.c0, FP2_ZERO) &&
    fp2Eq(a.c1.c1, FP2_ZERO) &&
    fp2Eq(a.c1.c2, FP2_ZERO);
}

// Exports for isolated testing
export {
  fp6Mul, fp6Sqr, fp6Add, fp6Sub, fp6Neg, fp6MulByV,
  fp12Mul, fp12Sqr, fp12Conj, fp12Inv,
  fp12FrobP, fp12FrobP2, fp12FrobP3,
  fp12ExpByX, finalExponentiation, millerLoop,
  fp12IsOne, FP12_ONE,
  twistFrobeniusP, twistFrobeniusP2,
  millerLoopRaw,
};
