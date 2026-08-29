/**
 * Fixed-base comb — compile-time table and its soundness check.
 *
 * The comb replaces the 257-round binary ladder for `u1·G` with 86 rounds over
 * a 7-entry precomputed table (measured optimum w=3; see
 * docs/experiments/script-size-optimizer-results.md). Because the base is a
 * compile-time constant, the whole table is computed here rather than on chain.
 *
 * The safety-critical half is `combSafeRounds`. The existing binary ladder uses
 * the CHEAP incomplete mixed-add everywhere but the last step, justified by an
 * interval argument over `c_i mod n` — and its own comment insists that
 * argument be REDONE, not assumed, by anything that changes the offset or the
 * iteration count. A comb changes both. So the argument is re-derived here as
 * executable interval arithmetic: a round may use the cheap add only when the
 * checker proves the pre-add accumulator cannot equal 0 or ±(any table value)
 * modulo n, for every scalar in the domain.
 */

import { describe, it, expect } from 'vitest';
import {
  combTable, combValue, combSafeRounds, combParams, scalarMulJS,
  P256_COMB_CURVE, P384_COMB_CURVE,
} from '../passes/comb.js';

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

describe('compile-time point arithmetic', () => {
  it('G doubles to the published 2G for P-256', () => {
    const two = scalarMulJS(2n, P256_COMB_CURVE.g, P256_COMB_CURVE);
    expect(two).not.toBeNull();
    expect(two!.x).toBe(0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978n);
    expect(two!.y).toBe(0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1n);
  });

  it('n·G is the point at infinity', () => {
    expect(scalarMulJS(P256_N, P256_COMB_CURVE.g, P256_COMB_CURVE)).toBeNull();
  });

  it('every table point is on the curve', () => {
    for (const curve of [P256_COMB_CURVE, P384_COMB_CURVE]) {
      const { p, a, b } = curve;
      for (const w of [2, 3, 4]) {
        const params = combParams(w, curve);
        expect(params, `no geometry for w=${w}`).not.toBeNull();
        for (const pt of combTable(w, params!.d, curve)) {
          if (pt === null) continue;
          const lhs = (pt.y * pt.y) % p;
          const rhs = (((pt.x * pt.x % p) * pt.x % p) + a * pt.x + b) % p;
          expect(((rhs % p) + p) % p).toBe(lhs);
        }
      }
    }
  });

  it('table entry j is combValue(j)·G', () => {
    const w = 3;
    const d = combParams(w, P256_COMB_CURVE)!.d;
    const table = combTable(w, d, P256_COMB_CURVE);
    for (let j = 1; j < (1 << w); j++) {
      const direct = scalarMulJS(combValue(j, d), P256_COMB_CURVE.g, P256_COMB_CURVE);
      expect(table[j], `entry ${j}`).toEqual(direct);
    }
  });

  it('entry 0 is the point at infinity and is never added', () => {
    const d = combParams(3, P256_COMB_CURVE)!.d;
    expect(combTable(3, d, P256_COMB_CURVE)[0]).toBeNull();
  });
});

describe('combSafeRounds — the interval argument, executable', () => {
  const w = 3;
  const params = combParams(w, P256_COMB_CURVE)!;
  const d = params.d;

  it('picks the offset that keeps the top digit non-zero', () => {
    // P-256 at w=3 lands on the same +3n the binary ladder hardcodes...
    expect(params.offsetMultiple).toBe(3n);
    expect(params.d).toBe(86);
    // ...but P-384 at w=3 does NOT. Assuming +3n there would let the leading
    // digit be zero, which puts the accumulator at infinity.
    const p384 = combParams(3, P384_COMB_CURVE)!;
    expect(p384.offsetMultiple).not.toBe(3n);
    expect(p384.lo >= (1n << BigInt(p384.w * p384.d - 1))).toBe(true);
    expect(p384.hi < (1n << BigInt(p384.w * p384.d))).toBe(true);
  });

  it('proves the early rounds safe for the cheap add', () => {
    const safe = combSafeRounds(params, P256_COMB_CURVE);
    expect(safe).toHaveLength(d);
    // The top round initialises the accumulator, so it performs no add.
    // Rounds where the accumulator interval is narrower than n must be provable.
    const provable = safe.filter(Boolean).length;
    expect(provable).toBeGreaterThan(d - 8);
  });

  it('refuses to prove the final rounds, where the interval exceeds n', () => {
    // The interval widens as i falls; once it can wrap a full residue class the
    // checker MUST give up rather than assume. A checker that proved every
    // round would be broken, not clever.
    const safe = combSafeRounds(params, P256_COMB_CURVE);
    expect(safe[0]).toBe(false);
  });

  it('is conservative under a deliberately widened domain', () => {
    // Doubling the scalar domain can only make rounds less provable.
    const strict = combSafeRounds(params, P256_COMB_CURVE);
    const loose = combSafeRounds({ ...params, hi: params.hi * 2n }, P256_COMB_CURVE);
    for (let i = 0; i < d; i++) {
      if (loose[i]) expect(strict[i], `round ${i} regressed`).toBe(true);
    }
  });

  it('works for P-384 too', () => {
    const p384 = combParams(w, P384_COMB_CURVE)!;
    const safe = combSafeRounds(p384, P384_COMB_CURVE);
    expect(safe).toHaveLength(p384.d);
    expect(safe.filter(Boolean).length).toBeGreaterThan(p384.d - 8);
  });
});
