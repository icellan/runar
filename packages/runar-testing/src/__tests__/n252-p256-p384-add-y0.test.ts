/**
 * N-252 — the NIST P-256 / P-384 adder must abort when it doubles a y = 0
 * point, as N-110 made the secp256k1 adder do.
 *
 * `cAffineAdd` (p256-p384-codegen.ts) takes the tangent when P == Q, with
 * slope (3px^2 - 3) / (2py). For py = 0 the denominator is 0, `cFieldInv` is
 * Fermat (inv(0) = 0), so the slope is 0 and the adder returned (p - 2px, 0).
 * Neither curve has a point with y = 0 (both have prime order, so no 2-torsion),
 * so only an off-curve operand gets here; `pNNNAdd` gates width and coordinate
 * canonicity but not curve membership, so (5, 0) reaches the tangent. The user
 * decision for N-110 applies: ABORT on that doubling, keep O + O = O (O is the
 * all-zero blob, which also has py = 0 and is exempted by px != 0).
 *
 * Oracle: `@bsv/sdk` `Spend.validate` via ScriptExecutionContract — the
 * compiled script, not the interpreter. A row is pinned as in the N-111
 * on-chain test: `assert(add(p, q) === e)` accepts at `e = expected` and
 * rejects at a different witness, and `assert(add(p, q) !== e)` rejects at
 * `expected`. An abort row rejects BOTH probes at the pre-fix answer.
 *
 * WHAT IT PROVES: on a consensus-shaped interpreter, for both curves, the
 * compiled pNNNAdd aborts on (5, 0) + (5, 0) (it used to return (p - 10, 0));
 * G + G = 2G (the tangent), G + 2G = 3G (the chord), O + O = O, G + (-G) = O
 * and (0, 5) + (0, 5) (a px = 0 doubling with py != 0) still give the values
 * an independent oracle (OpenSSL / from-scratch field arithmetic) gives.
 *
 * WHAT IT DOES NOT PROVE: that the other six tiers emit the same guard — that
 * is the conformance golden (byte-identical scripts for p256-primitives /
 * p384-primitives); or anything about verifyECDSA_P256 / _P384, whose adder
 * call is deliberately left unguarded (see cAffineAdd).
 */
import { describe, it, expect } from 'vitest';
import { createECDH } from 'node:crypto';
import { ScriptExecutionContract } from '../script-execution.js';

const CURVES = {
  p256: {
    openssl: 'prime256v1',
    bytes: 32,
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    add: 'p256Add',
    type: 'P256Point',
  },
  p384: {
    openssl: 'secp384r1',
    bytes: 48,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    add: 'p384Add',
    type: 'P384Point',
  },
} as const;

type Curve = (typeof CURVES)[keyof typeof CURVES];

const coord = (c: Curve, v: bigint) => v.toString(16).padStart(c.bytes * 2, '0');
const pt = (c: Curve, x: bigint, y: bigint) => coord(c, x) + coord(c, y);

/** k·G from OpenSSL, as the bare x‖y blob. */
function kG(c: Curve, k: bigint): string {
  const ecdh = createECDH(c.openssl);
  ecdh.setPrivateKey(Buffer.from(k.toString(16).padStart(c.bytes * 2, '0'), 'hex'));
  return ecdh.getPublicKey('hex').slice(2);
}

/** -P: (x, p - y). */
function neg(c: Curve, hex: string): string {
  const w = c.bytes * 2;
  return hex.slice(0, w) + coord(c, c.p - BigInt('0x' + hex.slice(w)));
}

/** The tangent of (0, 5) on y^2 = x^3 - 3x + b, computed from scratch. */
function doubleZeroX(c: Curve): string {
  const m = (v: bigint) => ((v % c.p) + c.p) % c.p;
  const pow = (b: bigint, e: bigint) => {
    let r = 1n;
    b = m(b);
    while (e > 0n) {
      if (e & 1n) r = (r * b) % c.p;
      b = (b * b) % c.p;
      e >>= 1n;
    }
    return r;
  };
  const s = m(-3n * pow(10n, c.p - 2n));
  const x = m(s * s);
  return pt(c, x, m(s * (0n - x) - 5n));
}

function probeSource(): string {
  const lines = [
    `import { SmartContract, assert, p256Add, p384Add } from 'runar-lang';`,
    `import type { P256Point, P384Point } from 'runar-lang';`,
    `class N252AddProbe extends SmartContract {`,
    `  constructor() { super(); }`,
  ];
  for (const c of Object.values(CURVES)) {
    lines.push(`  public eq_${c.add}(p: ${c.type}, q: ${c.type}, e: ${c.type}) { assert(${c.add}(p, q) === e); }`);
    lines.push(`  public ne_${c.add}(p: ${c.type}, q: ${c.type}, e: ${c.type}) { assert(${c.add}(p, q) !== e); }`);
  }
  lines.push('}');
  return lines.join('\n');
}

const flipLast = (hex: string) =>
  hex.slice(0, -2) + (parseInt(hex.slice(-2), 16) ^ 0xff).toString(16).padStart(2, '0');

describe('N-252: P-256 / P-384 add aborts when doubling a y = 0 point (Spend.validate)', () => {
  const probe = ScriptExecutionContract.fromSource(probeSource(), {}, 'N252AddProbe.runar.ts');

  for (const [name, c] of Object.entries(CURVES) as Array<[string, Curve]>) {
    const G = kG(c, 1n);
    const O = '00'.repeat(c.bytes * 2);
    const y0 = pt(c, 5n, 0n);

    it(`${name}: (5, 0) + (5, 0) aborts (it returned (p - 10, 0))`, { timeout: 120_000 }, () => {
      const old = pt(c, c.p - 10n, 0n);
      expect(probe.execute(`eq_${c.add}`, [y0, y0, old]).success, 'eq at the pre-fix answer').toBe(false);
      expect(probe.execute(`ne_${c.add}`, [y0, y0, old]).success, 'ne at the pre-fix answer').toBe(false);
    });

    const honest: Array<[string, string, string, string]> = [
      ['G + G = 2G', G, G, kG(c, 2n)],
      ['G + 2G = 3G', G, kG(c, 2n), kG(c, 3n)],
      ['O + O = O', O, O, O],
      ['G + (-G) = O', G, neg(c, G), O],
      ['(0, 5) + (0, 5): px = 0 doubling, py != 0', pt(c, 0n, 5n), pt(c, 0n, 5n), doubleZeroX(c)],
    ];
    for (const [why, p, q, want] of honest) {
      it(`${name}: ${why}`, { timeout: 120_000 }, () => {
        const ok = probe.execute(`eq_${c.add}`, [p, q, want]);
        expect(ok.success, ok.error).toBe(true);
        expect(probe.execute(`eq_${c.add}`, [p, q, flipLast(want)]).success).toBe(false);
        expect(probe.execute(`ne_${c.add}`, [p, q, want]).success).toBe(false);
      });
    }
  }
});
