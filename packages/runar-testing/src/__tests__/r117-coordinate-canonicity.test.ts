import { describe, it, expect } from 'vitest';
import {
  emitMethod,
  emitEcAdd, emitEcMul, emitEcNegate, emitEcOnCurve,
  emitP256Add, emitP256Mul, emitP256Negate, emitP256OnCurve,
  emitP384Add, emitP384Mul, emitP384Negate, emitP384OnCurve,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * R-117 — a Point's coordinates were never checked to be FIELD ELEMENTS, so
 * `affineAdd`'s case selectors compared two different spellings of the same
 * number and disagreed with themselves.
 *
 * CL-BUG-095 (commit ea79620a) made a Point exactly 2*w bytes. It did not make
 * the two numbers inside it canonical. `decomposePoint` BIN2NUMs each half as
 * an unsigned integer, so any value that fits in w bytes is accepted — `x + p`
 * included, whenever `x + p < 2^(8w)`. Every field operation downstream reduces
 * mod p, so `(x+p) ‖ y` behaves as the point `(x, y)` ARITHMETICALLY...
 *
 * ...but `affineAdd`'s two selectors are bare OP_NUMEQUAL on the raw decomposed
 * values:
 *
 *     cond   = (px == qx) AND (py == qy)      -- "these are the same point"
 *     notinf = NOT(px == qx AND NOT cond)     -- "these are not P and -P"
 *
 * Neither reduces first. So for P = (x, y) and P' = (x + p, y) — the SAME curve
 * point, differently spelled — both selectors read 0. The adder therefore takes
 * the CHORD path on two equal points, where `den_chord = qx - px ≡ 0 (mod p)`
 * and `fieldInv` is Fermat, so `inv(0) = 0`. Measured on @bsv/sdk's Spend,
 * before this commit, with x = 1 on secp256k1:
 *
 *     ecAdd(P, P)   -> c7ffffff…4bb00d333   (2P, correct)
 *     ecAdd(P, P')  -> fffffffe…81895441    (x = p-2, i.e. -2x; OFF CURVE)
 *
 * A script that SUCCEEDED and returned a blob that is not a point, for an input
 * that denotes P + P. The doubling fix and the P + (-P) fix that precede this
 * commit are both defeated by the same trick, because both are driven by these
 * two selectors.
 *
 * THE FIX IS TO REJECT, NOT TO REDUCE. `ecOnCurve` already answers "no" for a
 * non-canonical encoding (GAP-301, and its P-256/P-384 twin), so reducing here
 * would leave the predicate and the adder disagreeing about whether `P'` is a
 * point at all — the exact class of split-brain defect this branch keeps
 * finding. Rejecting keeps them aligned: `ecOnCurve` says "not a point", and
 * every value-producing consumer aborts. It is also the policy CL-BUG-095
 * already set for the width: predicates clamp and flag, value producers
 * OP_VERIFY.
 *
 * The gate goes on the USER-FACING value builtins (`ecAdd`, `ecMul`,
 * `ecNegate` and their P-256/P-384 twins) and deliberately NOT inside the
 * shared `decomposePoint` / `cDecomposePoint` helper: that helper is also on
 * `cEmitVerifyECDSA`'s path, where `decompressPubKey` has already decided —
 * with reasons recorded in its own docstring — that attacker-chosen bytes must
 * yield `false` from a total boolean builtin rather than abort the script.
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

const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P384_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn;

const CURVES = {
  secp256k1: {
    w: 32, p: SECP_P,
    // Smallest-x curve point; x + p must still fit in w bytes, which on
    // secp256k1 means x < 2^32 + 977.
    x: 1n,
    y: 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een,
    // The true double 2P, computed off-chain with bigint arithmetic.
    dbl: 'c7ffffffffffffffffffffffffffffffffffffffffffffffffffffff37fffd03'
       + '4298c557a7ddcc570e8bf054c4cad9e99f396b3ce19d50f1b91c9df4bb00d333',
    g: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
     + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
    emitAdd: emitEcAdd, emitMul: emitEcMul, emitNegate: emitEcNegate, emitOnCurve: emitEcOnCurve,
  },
  p256: {
    w: 32, p: P256_P,
    x: 5n,
    y: 0x459243b9aa581806fe913bce99817ade11ca503c64d9a3c533415c083248fbccn,
    dbl: '',
    g: '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
     + '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    emitAdd: emitP256Add, emitMul: emitP256Mul, emitNegate: emitP256Negate, emitOnCurve: emitP256OnCurve,
  },
  p384: {
    w: 48, p: P384_P,
    x: 2n,
    y: 0x8cdeadbbd04911a3c1931e26df3fa6439dca9c7eb286fbd46fc319f0e2bb780232baf57825fc0c1912ada2fefe84024cn,
    dbl: '',
    g: 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'
     + '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
    emitAdd: emitP384Add, emitMul: emitP384Mul, emitNegate: emitP384Negate, emitOnCurve: emitP384OnCurve,
  },
} as const;

describe.each(Object.entries(CURVES))('R-117 non-canonical coordinates are rejected — %s', (_name, C) => {
  const be = (v: bigint) => v.toString(16).padStart(2 * C.w, '0');
  const P = be(C.x) + be(C.y);
  const ALIAS = be(C.x + C.p) + be(C.y);          // same point, x written as x + p
  // A non-canonical Y. `y + p` does not fit in w bytes for these points, so
  // use `1 + p`, which denotes y = 1 — still a value BIN2NUM accepts and every
  // field op downstream silently reduces.
  const ALIAS_Y = be(C.x) + be(1n + C.p);
  const O = '00'.repeat(2 * C.w);

  it('the alias really is the same length and a different spelling', () => {
    expect(ALIAS).toHaveLength(4 * C.w);
    expect(ALIAS).not.toBe(P);
    expect(ALIAS_Y).toHaveLength(4 * C.w);
    expect(BigInt('0x' + ALIAS_Y.slice(2 * C.w))).toBeGreaterThanOrEqual(C.p);
  });

  it('ASSERTION — add(P, alias-of-P) is REJECTED (it used to return an off-curve blob)', () => {
    const r = run([pt(P), pt(ALIAS)], C.emitAdd);
    expect(r.rejected).toBe(true);
  }, 120_000);

  it('ASSERTION — add(alias-of-P, P) is REJECTED', () => {
    const r = run([pt(ALIAS), pt(P)], C.emitAdd);
    expect(r.rejected).toBe(true);
  }, 120_000);

  it('ASSERTION — a non-canonical Y is rejected too', () => {
    const r = run([pt(P), pt(ALIAS_Y)], C.emitAdd);
    expect(r.rejected).toBe(true);
  }, 120_000);

  it('ASSERTION — mul(alias-of-P, 3) is REJECTED', () => {
    const r = run([pt(ALIAS), num(3n)], C.emitMul);
    expect(r.rejected).toBe(true);
  }, 300_000);

  it('ASSERTION — negate(alias-of-P) is REJECTED', () => {
    const r = run([pt(ALIAS)], C.emitNegate);
    expect(r.rejected).toBe(true);
  }, 120_000);

  // -------------------------------------------------------------------------
  // Controls. Each one must STAY green; an over-strict gate reddens them.
  // -------------------------------------------------------------------------

  it('CONTROL — add(P, P) still doubles, and the result is on the curve', () => {
    const r = run([pt(P), pt(P)], C.emitAdd);
    expect(r.rejected).toBe(false);
    expect(r.top).not.toBe(P);
    expect(run([pt(r.top)], C.emitOnCurve).truthy).toBe(true);
    if (C.dbl) expect(r.top).toBe(C.dbl);
  }, 120_000);

  it('CONTROL — add(G, G) is unaffected', () => {
    const r = run([pt(C.g), pt(C.g)], C.emitAdd);
    expect(r.rejected).toBe(false);
    expect(run([pt(r.top)], C.emitOnCurve).truthy).toBe(true);
  }, 120_000);

  it('CONTROL — R-053 survives: add(G, O) = G and add(G, -G) = O', () => {
    expect(run([pt(C.g), pt(O)], C.emitAdd).top).toBe(C.g);
    const neg = run([pt(C.g)], C.emitNegate);
    expect(neg.rejected).toBe(false);
    expect(run([pt(C.g), pt(neg.top)], C.emitAdd).top).toBe(O);
  }, 120_000);

  it('CONTROL — mul(G, 3) is unaffected and lands on the curve', () => {
    const r = run([pt(C.g), num(3n)], C.emitMul);
    expect(r.rejected).toBe(false);
    expect(run([pt(r.top)], C.emitOnCurve).truthy).toBe(true);
  }, 300_000);

  it('CONTROL — the predicate stays TOTAL: onCurve(alias) is false, not an abort', () => {
    const r = run([pt(ALIAS)], C.emitOnCurve);
    expect(r.rejected).toBe(false);
    expect(r.truthy).toBe(false);
    expect(run([pt(C.g)], C.emitOnCurve).truthy).toBe(true);
  }, 120_000);

  // -------------------------------------------------------------------------
  // Boundary. The gate must be `< p`, not `<= p` and not some rounder bound:
  // p-1 is a legal field element, p is not.
  // -------------------------------------------------------------------------

  it('BOUNDARY — a coordinate of p-1 is accepted, a coordinate of p is not', () => {
    const justUnder = be(C.p - 1n) + be(1n);
    const exactlyP = be(C.p) + be(1n);
    expect(run([pt(justUnder)], C.emitNegate).rejected).toBe(false);
    expect(run([pt(exactlyP)], C.emitNegate).rejected).toBe(true);
  }, 120_000);

  it('BOUNDARY — a coordinate of p-1 on the Y half is accepted, p is not', () => {
    expect(run([pt(be(1n) + be(C.p - 1n))], C.emitNegate).rejected).toBe(false);
    expect(run([pt(be(1n) + be(C.p))], C.emitNegate).rejected).toBe(true);
  }, 120_000);
});
