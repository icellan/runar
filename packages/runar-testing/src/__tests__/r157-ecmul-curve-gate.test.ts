import { describe, it, expect } from 'vitest';
import {
  emitMethod,
  emitEcMul, emitEcMulGen, emitEcAdd, emitEcOnCurve,
  emitP256Mul, emitP256MulGen, emitP256Add, emitP256OnCurve,
  emitP384Mul, emitP384MulGen, emitP384Add, emitP384OnCurve,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * R-157 — the ladder's correctness argument holds only for points ON the
 * curve, every tier wrote that down, and nothing enforced it.
 *
 * `ecMul(P, k)` does not compute `k·P`. It computes `((k mod n) + 3n)·P`: the
 * MSB-first ladder adds `3n` so that a fixed high bit is always set, and `+3n`
 * is a NO-OP **only when ord(P) divides n**. Cofactor 1 gives ord(P) = n for
 * every point on the curve, so the trick is sound there and nowhere else. A
 * point off the curve lies on some other curve `y² = x³ + b′` whose order is
 * unrelated to n, and the whole computation silently answers a different
 * question.
 *
 * This is not an edge case, and it is not confined to small-order points.
 * Measured on @bsv/sdk's Spend before this commit, with the off-curve point
 * P = (5, 7) — which lies on `y² = x³ - 76`:
 *
 *     ecMul(P, 1n)  ->  c8b039d1…9438f2ff     which is NOT P
 *     ecMul(P, 2n)  ->  e673c72b…c8dde4c8     which is NOT 2P
 *
 * Both match `((k mod n) + 3n)·P` computed off-chain on that other curve
 * EXACTLY, which is how the mechanism was identified rather than guessed. So
 * `ecMul(P, 1n) != P`: the primitive violates its own contract for every
 * off-curve input, not merely for a contrived one.
 *
 * The degenerate sub-case is worse still. For a 2-torsion point of the other
 * curve — any `(x, 0)`, whose order is 2 — every multiple collapses:
 *
 *     ecMul((5, 0), k)  ->  the all-zero blob, for k = 1, 2, 3, 5
 *
 * because the ladder's unguarded mixed-add hits H = R = 0 mid-ladder, sets
 * Z3 = 0, and a Jacobian accumulator at infinity can never leave it. Combined
 * with R-053 — which taught `ecAdd` that the all-zero blob is the identity —
 * that turns a Schnorr-shaped verifier `s·G == R + e·P` into a free pass: pick
 * an off-curve `P` of order 2, `e·P` is O, `R + O` is R, and any `s` with
 * `R = s·G` verifies with no knowledge of any discrete log. R-053 was right and
 * is not being undone; this is the other half of the same seam.
 *
 * WHY THE GATE BELONGS IN `ecMul` AND NOT IN THE CALLER. The `+3n` offset is
 * INTERNAL to `ecMul` — a caller cannot see it, cannot know the obligation
 * exists without reading the codegen, and gains nothing by checking that
 * `ecMul` could not check more cheaply (`ecOnCurve` is 816 bytes against
 * `ecMul`'s 428 KB: 0.2%). "Callers who accept untrusted points must gate them
 * on ecOnCurve" was already written in the ladder's own docstring, in all seven
 * tiers, and the repository's own `schnorr-zkp` fixture takes its `pubKey` from
 * a DEPLOYER-supplied constructor slot where the idiom is not even reachable.
 *
 * WHY NOT `ecAdd` TOO, which is the other half of the boundary: `affineAdd`
 * implements the group law with no n-dependent trick, so on an off-curve
 * operand it returns the CORRECT sum on that operand's own curve. It does not
 * lie. And O — which is deliberately not on the curve — must keep flowing
 * through `ecAdd` for R-053 to hold. Gating the adder would break a working
 * primitive to fix a different one.
 *
 * O IS EXEMPTED, and that exemption is load-bearing: `ecMul(P, 0n)` returns the
 * all-zero blob, `ecAdd(P, -P)` returns it, the EC optimizer folds to it, and
 * `ecOnCurve(O)` is false by construction (0² ≠ 0³ + b). A bare on-curve gate
 * would reject the identity this codegen manufactures itself. The gate is
 * therefore `onCurve(P) OR P == O`.
 *
 * Everything below is EXECUTED on @bsv/sdk's `Spend` with real secp256k1.
 */

const bytes = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

function run(pushes: StackOp[], emitFn: (e: (op: StackOp) => void) => void) {
  const ops: StackOp[] = [...pushes];
  emitFn((op) => ops.push(op));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex);
  return {
    rejected: r.error !== undefined,
    top: r.stack.length ? hex(r.stack[r.stack.length - 1]!) : '',
    truthy: r.success,
  };
}
const pt = (h: string) => ({ op: 'push', value: bytes(h) }) as StackOp;
const num = (n: bigint) => ({ op: 'push', value: n }) as StackOp;

const CURVES = {
  secp256k1: {
    w: 32,
    g: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
     + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    emitMul: emitEcMul, emitMulGen: emitEcMulGen, emitAdd: emitEcAdd, emitOnCurve: emitEcOnCurve,
  },
  p256: {
    w: 32,
    g: '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
     + '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    emitMul: emitP256Mul, emitMulGen: emitP256MulGen, emitAdd: emitP256Add, emitOnCurve: emitP256OnCurve,
  },
  p384: {
    w: 48,
    g: 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'
     + '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
    emitMul: emitP384Mul, emitMulGen: emitP384MulGen, emitAdd: emitP384Add, emitOnCurve: emitP384OnCurve,
  },
} as const;

describe.each(Object.entries(CURVES))('R-157 ecMul refuses a point it cannot multiply — %s', (_n, C) => {
  const be = (v: bigint) => v.toString(16).padStart(2 * C.w, '0');
  const O = '00'.repeat(2 * C.w);
  // (5, 0) is a 2-torsion point of y² = x³ - 125, not of this curve.
  const OFF_ORDER2 = be(5n) + be(0n);
  // (5, 7) is an ordinary point of y² = x³ + (49 - 125), not of this curve.
  const OFF_GENERIC = be(5n) + be(7n);

  it('the witnesses really are off this curve', () => {
    expect(run([pt(OFF_ORDER2)], C.emitOnCurve).truthy).toBe(false);
    expect(run([pt(OFF_GENERIC)], C.emitOnCurve).truthy).toBe(false);
    expect(run([pt(C.g)], C.emitOnCurve).truthy).toBe(true);
  }, 120_000);

  it('ASSERTION — mul(off-curve order-2 point, k) is REJECTED (it used to return O for every k)', () => {
    for (const k of [1n, 2n, 3n]) {
      expect(run([pt(OFF_ORDER2), num(k)], C.emitMul).rejected).toBe(true);
    }
  }, 600_000);

  it('ASSERTION — mul(generic off-curve point, k) is REJECTED (it used to answer on another curve)', () => {
    for (const k of [1n, 2n]) {
      expect(run([pt(OFF_GENERIC), num(k)], C.emitMul).rejected).toBe(true);
    }
  }, 600_000);

  // -------------------------------------------------------------------------
  // Controls with teeth. An over-strict gate reddens every one of these.
  // -------------------------------------------------------------------------

  it('CONTROL — mul(G, k) still works and lands on the curve', () => {
    for (const k of [1n, 2n, 7n]) {
      const r = run([pt(C.g), num(k)], C.emitMul);
      expect(r.rejected).toBe(false);
      expect(run([pt(r.top)], C.emitOnCurve).truthy).toBe(true);
    }
  }, 900_000);

  it('CONTROL — mul(G, 1) is G: the identity the ladder used to get wrong off-curve', () => {
    expect(run([pt(C.g), num(1n)], C.emitMul).top).toBe(C.g);
  }, 300_000);

  it('CONTROL — mulGen(k) is unaffected, and agrees with mul(G, k)', () => {
    const viaGen = run([num(5n)], C.emitMulGen);
    const viaMul = run([pt(C.g), num(5n)], C.emitMul);
    expect(viaGen.rejected).toBe(false);
    expect(viaGen.top).toBe(viaMul.top);
  }, 900_000);

  it('CONTROL — O IS EXEMPT: mul(O, k) is still O, for every k', () => {
    for (const k of [0n, 1n, 2n, 7n]) {
      const r = run([pt(O), num(k)], C.emitMul);
      expect(r.rejected).toBe(false);
      expect(r.top).toBe(O);
    }
    // ...which is exactly why a bare on-curve gate would not do: O is not on it.
    expect(run([pt(O)], C.emitOnCurve).truthy).toBe(false);
  }, 900_000);

  it('CONTROL — mul(P, 0n) still produces O, so the identity keeps flowing', () => {
    const r = run([pt(C.g), num(0n)], C.emitMul);
    expect(r.rejected).toBe(false);
    expect(r.top).toBe(O);
  }, 300_000);

  it('CONTROL — ecAdd is deliberately NOT gated: add(G, O) = G and O stays usable', () => {
    expect(run([pt(C.g), pt(O)], C.emitAdd).top).toBe(C.g);
    expect(run([pt(O), pt(C.g)], C.emitAdd).top).toBe(C.g);
  }, 300_000);
});

describe('R-157 the Schnorr-shaped forgery the gate closes', () => {
  const C = CURVES.secp256k1;
  const O = '00'.repeat(64);
  const OFF_ORDER2 = (5n).toString(16).padStart(64, '0') + '0'.repeat(64);

  it('e·P collapsing to O would make `s·G == R + e·P` free; it is now rejected', () => {
    // The verifier's shape, with the attacker choosing P and R.
    // Step 1 used to succeed and return O. It must now abort.
    const eP = run([pt(OFF_ORDER2), num(12345n)], C.emitMul);
    expect(eP.rejected).toBe(true);

    // Had it not aborted, R-053's (correct) identity rule would have carried
    // the forgery the rest of the way: R + O = R.
    const rPoint = run([pt(C.g), num(9n)], C.emitMul);
    expect(rPoint.rejected).toBe(false);
    expect(run([pt(rPoint.top), pt(O)], C.emitAdd).top).toBe(rPoint.top);
  }, 900_000);
});
