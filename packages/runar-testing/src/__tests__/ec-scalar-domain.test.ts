import { describe, it, expect } from 'vitest';
import { createECDH } from 'node:crypto';
import { Point as BsvPoint, BigNumber } from '@bsv/sdk';
import {
  emitMethod,
  emitEcAdd, emitEcMul, emitEcMulGen,
  emitP256Mul, emitP256MulGen,
  emitP384Mul, emitP384MulGen,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * The DOMAIN of `ecMul` / `pNNNMul`: every scalar, not just [1, n−1].
 *
 * The ladder runs over k′ = k + 3n and relies on bit 257 (P-256/secp256k1) or
 * bit 385 (P-384) being the top set bit, which holds only while
 * 2^257 ≤ k′ < 2^258. For k ∈ [0, n−1] that is guaranteed; outside it the
 * high bit falls off the end of the loop and the ladder silently returns a
 * DIFFERENT multiple of P. The scalar is routinely contract input (an unlock
 * argument), so "unspecified" here means an attacker picks the multiple.
 *
 * The fix reduces k to [0, n−1] up front, which also fixes negative scalars
 * and makes k ≡ 0 (mod n) the point at infinity — which affine coordinates
 * cannot represent, so it stays the all-zero blob, exactly as before.
 *
 * This also removes a divergence: `packages/runar-testing`'s ANF interpreter
 * has ALWAYS reduced the scalar mod n (`ecScalarMul` / `nistScalarMul` both
 * start with `k mod n`), so before this change the differential oracle and
 * the script it grades disagreed for every k ≥ n.
 *
 * Oracles: @bsv/sdk's own `Point.mul` for secp256k1, OpenSSL via
 * `crypto.createECDH` for the NIST curves, both cross-checked against a
 * from-scratch double-and-add written from the curve parameters alone.
 * Everything runs through the real @bsv/sdk `Spend` interpreter.
 */

const CURVES = {
  secp256k1: {
    openssl: 'secp256k1',
    bytes: 32,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
    a: 0n,
    b: 7n,
    gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
    gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    emitMul: emitEcMul,
    emitMulGen: emitEcMulGen,
  },
  p256: {
    openssl: 'prime256v1',
    bytes: 32,
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    a: -3n,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
    gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
    emitMul: emitP256Mul,
    emitMulGen: emitP256MulGen,
  },
  p384: {
    openssl: 'secp384r1',
    bytes: 48,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    a: -3n,
    b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
    gx: 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7n,
    gy: 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5fn,
    emitMul: emitP384Mul,
    emitMulGen: emitP384MulGen,
  },
} as const;

type Curve = (typeof CURVES)[keyof typeof CURVES];
type Aff = { x: bigint; y: bigint } | null;

// --- from-scratch double-and-add over y² = x³ + ax + b ----------------------

function makeArith(c: Curve) {
  const p = c.p;
  const m = (v: bigint) => ((v % p) + p) % p;
  const inv = (a: bigint) => {
    let r = 1n;
    let b = m(a);
    let e = p - 2n;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % p;
      b = (b * b) % p;
      e >>= 1n;
    }
    return r;
  };
  const dbl = (P0: Aff): Aff => {
    if (P0 === null) return null;
    const s = m(m(3n * P0.x * P0.x + c.a) * inv(2n * P0.y));
    const x = m(s * s - 2n * P0.x);
    return { x, y: m(s * (P0.x - x) - P0.y) };
  };
  const add = (P0: Aff, Q: Aff): Aff => {
    if (P0 === null) return Q;
    if (Q === null) return P0;
    if (P0.x === Q.x) return m(P0.y + Q.y) === 0n ? null : dbl(P0);
    const s = m(m(Q.y - P0.y) * inv(m(Q.x - P0.x)));
    const x = m(s * s - P0.x - Q.x);
    return { x, y: m(s * (P0.x - x) - P0.y) };
  };
  const mul = (k: bigint, P0: Aff): Aff => {
    let r: Aff = null;
    let a = P0;
    let e = k;
    while (e > 0n) {
      if (e & 1n) r = add(r, a);
      a = dbl(a);
      e >>= 1n;
    }
    return r;
  };
  return { add, dbl, mul };
}

// --- harness ----------------------------------------------------------------

const blob = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

function exec(ops: StackOp[]): string {
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex) as never as { stack: Uint8Array[] };
  return r.stack.length ? Buffer.from(r.stack[r.stack.length - 1]!).toString('hex') : '(empty)';
}

function curveMul(c: Curve, pHex: string, k: bigint): string {
  const ops: StackOp[] = [
    { op: 'push', value: blob(pHex) } as StackOp,
    { op: 'push', value: k } as StackOp,
  ];
  c.emitMul((o: StackOp) => ops.push(o));
  return exec(ops);
}

function curveMulGen(c: Curve, k: bigint): string {
  const ops: StackOp[] = [{ op: 'push', value: k } as StackOp];
  c.emitMulGen((o: StackOp) => ops.push(o));
  return exec(ops);
}

/** k·G according to the tier-external implementation for this curve. */
function externalMulGen(c: Curve, k: bigint): string {
  const w = c.bytes * 2;
  if (c.openssl === 'secp256k1') {
    const r = new BsvPoint(c.gx.toString(16), c.gy.toString(16))
      .mul(new BigNumber(k.toString(16), 16));
    return r.getX().toHex(c.bytes) + r.getY().toHex(c.bytes);
  }
  const ecdh = createECDH(c.openssl);
  ecdh.setPrivateKey(Buffer.from(k.toString(16).padStart(w, '0'), 'hex'));
  const pub = ecdh.getPublicKey('hex'); // 04 ‖ x ‖ y
  expect(pub.slice(0, 2)).toBe('04');
  return pub.slice(2);
}

for (const [name, c] of Object.entries(CURVES) as Array<[string, Curve]>) {
  const w = c.bytes * 2;
  const A = makeArith(c);
  const G: NonNullable<Aff> = { x: c.gx, y: c.gy };
  const G_HEX = c.gx.toString(16).padStart(w, '0') + c.gy.toString(16).padStart(w, '0');
  const hexOf = (pt: NonNullable<Aff>) =>
    pt.x.toString(16).padStart(w, '0') + pt.y.toString(16).padStart(w, '0');
  /** The value k·G MUST take, i.e. (k mod n)·G. */
  const expected = (k: bigint) => {
    const r = ((k % c.n) + c.n) % c.n;
    return r === 0n ? '00'.repeat(c.bytes * 2) : hexOf(A.mul(r, G)!);
  };

  describe(`${name} scalar domain`, () => {
    it('oracles agree: from-scratch double-and-add === external implementation', () => {
      for (const k of [1n, 2n, 5n, 7n, 11n, c.n - 1n]) {
        expect(hexOf(A.mul(k, G)!)).toBe(externalMulGen(c, k));
      }
    });

    // ---- k ≥ n: the ladder dropped the overflow bit -------------------------

    for (const [label, k] of [
      ['n + 5', c.n + 5n],
      ['2n + 7', 2n * c.n + 7n],
      ['5n + 11', 5n * c.n + 11n],
    ] as Array<[string, bigint]>) {
      it(`Mul(G, ${label}) === ${(k % c.n).toString()}·G`, () => {
        expect(curveMul(c, G_HEX, k)).toBe(expected(k));
      });
    }

    it('Mul(G, k) for a scalar far above n (2^300-ish) reduces mod n', () => {
      const k = (1n << 300n) + 12345n;
      expect(curveMul(c, G_HEX, k)).toBe(expected(k));
    });

    it('MulGen(2n + 7) === 7·G', () => {
      expect(curveMulGen(c, 2n * c.n + 7n)).toBe(expected(2n * c.n + 7n));
    });

    // ---- negative scalars ---------------------------------------------------

    for (const k of [-1n, -3n, -12345n]) {
      it(`Mul(G, ${k}) === (n${k})·G`, () => {
        expect(curveMul(c, G_HEX, k)).toBe(expected(k));
      });
    }

    it('Mul(G, −(n + 1)) === (n − 1)·G', () => {
      const k = -(c.n + 1n);
      expect(curveMul(c, G_HEX, k)).toBe(expected(k));
    });

    // ---- k ≡ 0 (mod n): the point at infinity -------------------------------
    //
    // Affine x‖y cannot encode O, and `fieldInv` is Fermat so inv(0) = 0; the
    // ladder therefore yields the all-zero blob. Pinned, not aspirational:
    // this is the one input for which the result is not a curve point, and a
    // contract must treat the all-zero point as a rejection.

    it('Mul(G, 0) is the all-zero point (O is not representable)', () => {
      expect(curveMul(c, G_HEX, 0n)).toBe('00'.repeat(c.bytes * 2));
    });

    it('Mul(G, n) is the all-zero point — same element as k = 0', () => {
      expect(curveMul(c, G_HEX, c.n)).toBe('00'.repeat(c.bytes * 2));
    });

    it('Mul(G, 3n) is the all-zero point', () => {
      expect(curveMul(c, G_HEX, 3n * c.n)).toBe('00'.repeat(c.bytes * 2));
    });

    // ---- controls: the in-range domain is untouched --------------------------

    for (const k of [1n, 2n, 5n, 7n]) {
      it(`control: Mul(G, ${k}) === ${k}·G`, () => {
        expect(curveMul(c, G_HEX, k)).toBe(externalMulGen(c, k));
      });
    }

    it('control: Mul(G, n − 1) === −G', () => {
      expect(curveMul(c, G_HEX, c.n - 1n)).toBe(externalMulGen(c, c.n - 1n));
    });
  });
}

// ---------------------------------------------------------------------------
// The `ec-mulgen-linear` optimizer rule rides on this reduce
// ---------------------------------------------------------------------------
//
// optimizer/ec-rules.json rewrites ecAdd(ecMulGen(k1), ecMulGen(k2)) into
// ecMulGen(k1 + k2) when BOTH operands are compile-time constants, folding the
// sum mod n at rewrite time. Runtime operands are left alone in every tier —
// the Go rule engine used to fire on them too, emitting a plain `bin_op "+"`
// with NO mod-n, and was brought into line with the other six because it made
// the same source compile to a different script (see opOperandsAreConst in
// compilers/go/frontend/ec_rules_engine.go). That divergence was never a
// miscompilation precisely because the reduce above puts k1 + k2 back into
// [0, n−1] inside the ladder; remove the reduce and the runtime spelling of
// this rule becomes wrong the moment anyone re-enables it.
//
// The reduce is load-bearing for the plain builtin regardless: unlock-argument
// scalars are attacker-chosen and may be ≥ n or negative.
//
// Both spellings are pinned here, at the two scalars where they could differ,
// so that removing the reduce as "redundant" fails loudly.

describe('ec-mulgen-linear depends on the scalar reduce', () => {
  const c = CURVES.secp256k1;
  const A = makeArith(c);
  const w = c.bytes * 2;
  const G: NonNullable<Aff> = { x: c.gx, y: c.gy };
  const hexOf = (pt: NonNullable<Aff>) =>
    pt.x.toString(16).padStart(w, '0') + pt.y.toString(16).padStart(w, '0');
  const ZERO = '00'.repeat(c.bytes * 2);

  function ecAdd(aHex: string, bHex: string): string {
    const ops: StackOp[] = [
      { op: 'push', value: blob(aHex) } as StackOp,
      { op: 'push', value: blob(bHex) } as StackOp,
    ];
    emitEcAdd((o: StackOp) => ops.push(o));
    return exec(ops);
  }

  // k1 = n − 1, k2 = 5. The rewritten sum is n + 4, which is ≥ n and therefore
  // outside the ladder's domain without the reduce.
  it('rewritten: MulGen((n − 1) + 5) === 4·G', () => {
    expect(curveMulGen(c, c.n - 1n + 5n)).toBe(hexOf(A.mul(4n, G)!));
  });

  it('unrewritten: Add(MulGen(n − 1), MulGen(5)) === 4·G', () => {
    const negG = curveMulGen(c, c.n - 1n);
    const fiveG = curveMulGen(c, 5n);
    expect(ecAdd(negG, fiveG)).toBe(hexOf(A.mul(4n, G)!));
  });

  // k1 + k2 ≡ 0 (mod n): the rewrite yields ecMulGen(0) — the all-zero point —
  // while the unrewritten spelling is ecAdd(P, −P). Those agree only because
  // affineAdd was taught to return the all-zero point for P == −Q; selecting
  // the tangent on px == qx alone made the unrewritten spelling return 2·k1·G,
  // i.e. the same source compiling to two different answers depending on
  // whether the optimizer fired.
  it('k1 + k2 ≡ 0 (mod n): both spellings give the all-zero point', () => {
    expect(curveMulGen(c, 3n + (c.n - 3n))).toBe(ZERO);
    expect(ecAdd(curveMulGen(c, 3n), curveMulGen(c, c.n - 3n))).toBe(ZERO);
  });
});
