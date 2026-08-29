/**
 * Fixed-base comb: compile-time table, and the soundness check that decides
 * where the cheap incomplete addition may be used.
 *
 * The binary ladder in `p256-p384-codegen.ts` uses the cheap mixed add at every
 * step but the last, justified by an interval argument over `c_i mod n`. That
 * comment is emphatic that the argument must be RE-DERIVED, not assumed, by
 * anything which changes the offset, the iteration count, or the reduce — and a
 * comb changes all three. `combSafeRounds` below is that re-derivation, written
 * as executable interval arithmetic rather than prose, so a round only gets the
 * cheap add when the exception is proved unreachable. Rounds it cannot prove
 * fall back to the complete add-or-double form.
 *
 * Nothing here emits Script. It is pure arithmetic over bigints, run once per
 * compilation, and unit-tested against published curve vectors.
 */

// ---------------------------------------------------------------------------
// Curve description
// ---------------------------------------------------------------------------

export interface CombPoint {
  x: bigint;
  y: bigint;
}

export interface CombCurve {
  /** Field prime. */
  p: bigint;
  /** Curve coefficient a. Both NIST curves use a = -3. */
  a: bigint;
  /** Curve coefficient b. */
  b: bigint;
  /** Group order. */
  n: bigint;
  /** Base point. */
  g: CombPoint;
}

/**
 * Comb geometry for one window width, chosen so the top digit is never zero.
 *
 * The binary ladder hardcodes `k + 3n`, which puts the scalar's top bit at a
 * fixed position and so keeps the accumulator off the point at infinity. A comb
 * needs the same guarantee, but its first round reads bit `w*d - 1`, so the
 * offset has to be chosen against `w*d` rather than assumed. `offsetMultiple`
 * is the smallest `m` for which every `k + m*n` has bit `w*d - 1` set:
 *
 *     m*n >= 2^(w*d - 1)   and   (m+1)*n - 1 < 2^(w*d)
 *
 * `m*n ≡ 0 (mod n)` so the result is unchanged. For P-256 at w=3 the search
 * returns m=3, d=86 — i.e. exactly the `+3n` the binary ladder already uses.
 * For P-384 at w=3 it returns m=5, d=129; assuming `+3n` there would have left
 * the top digit free to be zero.
 */
export interface CombParams {
  w: number;
  /** Rounds, and the block width. Digit `i` reads bits `i, i+d, ..., i+(w-1)d`. */
  d: number;
  /** Multiple of n added to the reduced scalar. */
  offsetMultiple: bigint;
  /** Inclusive scalar domain after the offset. */
  lo: bigint;
  hi: bigint;
}

const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

const P384_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn;
const P384_N = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n;
const P384_B = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn;
const P384_GX = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n;
const P384_GY = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn;

function bitLength(v: bigint): number {
  return v === 0n ? 0 : v.toString(2).length;
}

function makeCurve(p: bigint, b: bigint, n: bigint, gx: bigint, gy: bigint): CombCurve {
  return { p, a: -3n, b, n, g: { x: gx, y: gy } };
}

/**
 * Geometry for window width `w`, or null if no offset in the search range puts
 * a guaranteed set bit at the top of the first digit. Returning null rather
 * than guessing keeps the caller from silently combing a scalar whose leading
 * digit can vanish.
 */
export function combParams(w: number, c: CombCurve): CombParams | null {
  const base = Math.ceil(bitLength(c.n) / w);
  for (let d = base; d <= base + 2; d++) {
    const B = BigInt(w * d);
    const top = 1n << (B - 1n);
    const cap = 1n << B;
    for (let m = 1n; m <= 16n; m++) {
      const lo = m * c.n;
      const hi = (m + 1n) * c.n - 1n;
      if (lo >= top && hi < cap) {
        return { w, d, offsetMultiple: m, lo, hi };
      }
    }
  }
  return null;
}

export const P256_COMB_CURVE: CombCurve = makeCurve(P256_P, P256_B, P256_N, P256_GX, P256_GY);
export const P384_COMB_CURVE: CombCurve = makeCurve(P384_P, P384_B, P384_N, P384_GX, P384_GY);

// ---------------------------------------------------------------------------
// Affine arithmetic (compile time only)
// ---------------------------------------------------------------------------

const mod = (v: bigint, m: bigint): bigint => ((v % m) + m) % m;

function inv(v: bigint, m: bigint): bigint {
  // Extended Euclid. `v` is never 0 on the paths below.
  let [old_r, r] = [mod(v, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

/** Affine addition. `null` is the point at infinity. */
export function affineAddJS(
  P: CombPoint | null, Q: CombPoint | null, c: CombCurve,
): CombPoint | null {
  if (P === null) return Q;
  if (Q === null) return P;
  const { p, a } = c;
  if (P.x === Q.x) {
    if (mod(P.y + Q.y, p) === 0n) return null; // P == -Q
    // Tangent.
    const num = mod(3n * P.x * P.x + a, p);
    const lam = mod(num * inv(mod(2n * P.y, p), p), p);
    const x = mod(lam * lam - 2n * P.x, p);
    return { x, y: mod(lam * (P.x - x) - P.y, p) };
  }
  const lam = mod(mod(Q.y - P.y, p) * inv(mod(Q.x - P.x, p), p), p);
  const x = mod(lam * lam - P.x - Q.x, p);
  return { x, y: mod(lam * (P.x - x) - P.y, p) };
}

/** Double-and-add. `null` is the point at infinity. */
export function scalarMulJS(k: bigint, P: CombPoint | null, c: CombCurve): CombPoint | null {
  let r: CombPoint | null = null;
  let base = P;
  let e = mod(k, c.n);
  while (e > 0n) {
    if (e & 1n) r = affineAddJS(r, base, c);
    base = affineAddJS(base, base, c);
    e >>= 1n;
  }
  return r;
}

// ---------------------------------------------------------------------------
// Comb table
// ---------------------------------------------------------------------------

/**
 * The multiple of G that table entry `j` represents.
 *
 * Comb round `i` consumes bits `{i, i+d, i+2d, ...}` of the scalar — one from
 * each block — so entry `j` stands for the sum of `2^(t*d)` over the set bits
 * `t` of `j`.
 */
export function combValue(j: number, d: number): bigint {
  let v = 0n;
  for (let t = 0; (j >> t) !== 0; t++) {
    if ((j >> t) & 1) v += 1n << BigInt(t * d);
  }
  return v;
}

/** `T[j] = combValue(j)·G`. Index 0 is the point at infinity and is never added. */
export function combTable(w: number, d: number, c: CombCurve): Array<CombPoint | null> {
  const table: Array<CombPoint | null> = [];
  for (let j = 0; j < (1 << w); j++) {
    table.push(j === 0 ? null : scalarMulJS(combValue(j, d), c.g, c));
  }
  return table;
}

// ---------------------------------------------------------------------------
// Soundness: where may the cheap incomplete addition be used?
// ---------------------------------------------------------------------------

/**
 * Bounds on the comb accumulator's multiplier before round `i`'s doubling.
 *
 * After processing rounds `d-1 .. i`, the accumulator is `c_i·G` with
 *
 *     c_i = Σ_m 2^(m·d) · floor(K_m / 2^i)
 *
 * where `K_m` is the m-th `d`-bit block of the expanded scalar. Each floor
 * discards less than one unit of its block, so
 *
 *     k/2^i - Σ_m 2^(m·d)  <  c_i  <=  k/2^i
 *
 * and with `k` confined to `[scalarLo, scalarHi]` that gives a contiguous
 * interval. The slack term is bounded by `2^(w·d)/(2^d - 1)`, far below `n`,
 * which is why the interval stays narrower than the group order for all but the
 * last few rounds — exactly the property the binary ladder's argument relies on.
 */
function accumulatorInterval(i: number, params: CombParams): { lo: bigint; hi: bigint } {
  let slack = 0n;
  for (let m = 0; m < params.w; m++) slack += 1n << BigInt(m * params.d);
  const shift = BigInt(i);
  const hi = params.hi >> shift;
  const lo = (params.lo >> shift) - slack;
  return { lo: lo < 0n ? 0n : lo, hi };
}

/** Does `[lo, hi]` contain any integer congruent to `target` modulo `n`? */
function intervalHitsResidue(lo: bigint, hi: bigint, target: bigint, n: bigint): boolean {
  if (hi < lo) return false;
  if (hi - lo + 1n >= n) return true; // wraps a full residue class
  const t = mod(target, n);
  // Smallest value >= lo that is congruent to t (mod n).
  const first = lo + mod(t - lo, n);
  return first <= hi;
}

/**
 * Per-round verdict: may round `i` use the cheap incomplete mixed add?
 *
 * The exception the cheap formula cannot represent is a pre-add accumulator
 * equal to the addend, its negation, or the point at infinity. After round
 * `i`'s doubling the accumulator is `2·c_{i+1}·G`, and the addend is
 * `combValue(j)·G` for whichever digit `j` the scalar selects — so the round is
 * safe exactly when, for every `j`,
 *
 *     2·c_{i+1} ≢ 0, +combValue(j), -combValue(j)   (mod n)
 *
 * over the whole interval of `c_{i+1}`. Both `G` and every table entry are
 * compile-time constants and the curves have cofactor 1, so `ord(G) = n` and
 * this is decidable here. Anything the checker cannot prove gets the complete
 * add-or-double form instead; `true` is never assumed.
 *
 * Index `d-1` is `false` by construction: that round initialises the
 * accumulator from the table and performs no addition at all.
 */
export function combSafeRounds(params: CombParams, c: CombCurve): boolean[] {
  const { w, d } = params;
  const values: bigint[] = [];
  for (let j = 1; j < (1 << w); j++) values.push(combValue(j, d));

  const safe: boolean[] = [];
  for (let i = 0; i < d; i++) {
    if (i === d - 1) { safe[i] = false; continue; }
    const { lo, hi } = accumulatorInterval(i + 1, params);
    const dLo = 2n * lo;
    const dHi = 2n * hi;
    let ok = !intervalHitsResidue(dLo, dHi, 0n, c.n);
    for (const v of values) {
      if (!ok) break;
      ok = !intervalHitsResidue(dLo, dHi, v, c.n)
        && !intervalHitsResidue(dLo, dHi, -v, c.n);
    }
    safe[i] = ok;
  }
  return safe;
}
