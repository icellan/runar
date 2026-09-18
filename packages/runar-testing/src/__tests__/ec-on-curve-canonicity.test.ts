import { describe, it, expect } from 'vitest';
import { ECDH } from 'node:crypto';
import {
  emitMethod,
  emitEcOnCurve, emitEcAdd,
  emitP256OnCurve, emitP256Add,
  emitP384OnCurve, emitP384Add,
} from 'runar-compiler';
import type { StackOp } from 'runar-ir-schema';
import { ScriptVM } from '../index.js';

/**
 * GAP-301 — coordinate canonicity in the on-curve checks.
 *
 * A `Point` is a bare x‖y byte blob, and every emitter turns those bytes into
 * a script number and then reduces mod p. So the blob (x + p)‖y satisfies the
 * curve equation exactly as x‖y does. `ecOnCurve` (secp256k1) range-checks the
 * coordinates and rejects that; `p256OnCurve` / `p384OnCurve` did NOT — they
 * emitted the curve equation alone, so they accepted a coordinate that is not
 * a canonical field element.
 *
 * That matters because the on-curve check is exactly what the P-256 / P-384
 * codegen tells contract authors to gate untrusted points on, and two things
 * downstream read the coordinates BEFORE any reduction:
 *
 *   - `pNNNAdd`'s doubling test is `OP_NUMEQUAL(px, qx)` on the raw values, so
 *     P and its non-canonical twin take the CHORD path, divide by
 *     (qx − px) = p ≡ 0, and — `fieldInv` being Fermat, inv(0) = 0 — produce a
 *     point that is not 2P and is not even on the curve, with the script
 *     succeeding. That is the `pNNNAdd(P, P')` case pinned below.
 *   - a point's identity as *bytes* (nullifier / commitment / equality test)
 *     stops being unique once two encodings both pass the gate.
 *
 * Oracle: OpenSSL, via Node's `crypto.ECDH.convertKey()`, which parses an
 * uncompressed 04‖x‖y point and rejects both off-curve points and out-of-range
 * field elements. Every Rúnar result here is produced by running the emitted
 * script through the real @bsv/sdk interpreter.
 *
 * NOTE on the y half of the guard. An earlier version of this comment claimed
 * it had "no constructible witness". That was wrong, and wrong in the direction
 * that matters. A non-canonical y needs y < 2^(8·w) − p — about 2^224 for
 * P-256, 2^128 for P-384, 2^32 for secp256k1 — and by RANDOM search that is a
 * 2^-32 / 2^-256 / 2^-224 event, so P-256 alone is already only ~4·10⁹ trials,
 * hours on a GPU, not "infeasible".
 *
 * But nobody has to search at all. Fix y and the curve equation becomes a
 * CUBIC in x, x³ + a·x + (b − y²) ≡ 0 (mod p), whose roots are found in
 * milliseconds by gcd(x^p − x, f) over F_p. So a small-y witness exists for
 * ALL THREE curves and is computed below (`smallYPoint`) rather than assumed
 * away — which is the strongest argument for keeping the y half of the guard.
 */

const CURVES = {
  secp256k1: {
    openssl: 'secp256k1',
    bytes: 32,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    // y² = x³ + ax + b
    a: 0n,
    b: 7n,
    emitOnCurve: emitEcOnCurve,
    emitAdd: emitEcAdd,
    /** secp256k1's guard predates this fix — it is the control, already green. */
    alreadyGuarded: true,
  },
  p256: {
    openssl: 'prime256v1',
    bytes: 32,
    p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
    a: -3n,
    b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
    emitOnCurve: emitP256OnCurve,
    emitAdd: emitP256Add,
    alreadyGuarded: false,
  },
  p384: {
    openssl: 'secp384r1',
    bytes: 48,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffffn,
    a: -3n,
    b: 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aefn,
    emitOnCurve: emitP384OnCurve,
    emitAdd: emitP384Add,
    alreadyGuarded: false,
  },
} as const;

type Curve = (typeof CURVES)[keyof typeof CURVES];

// --- field helpers (from the curve parameters alone) ------------------------

const mod = (v: bigint, p: bigint) => ((v % p) + p) % p;

function powm(base: bigint, exp: bigint, p: bigint): bigint {
  let r = 1n;
  let b = mod(base, p);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % p;
    b = (b * b) % p;
    e >>= 1n;
  }
  return r;
}

/** √a mod p for p ≡ 3 (mod 4) — true for all three curves. */
function sqrtMod(a: bigint, p: bigint): bigint | null {
  const r = powm(a, (p + 1n) / 4n, p);
  return (r * r) % p === mod(a, p) ? r : null;
}

function rhs(c: Curve, x: bigint): bigint {
  return mod(x * x * x + c.a * x + c.b, c.p);
}

function isOnCurve(c: Curve, x: bigint, y: bigint): boolean {
  return mod(y * y, c.p) === rhs(c, x);
}

/**
 * The smallest on-curve x for which x + p still fits the coordinate width —
 * the only shape of witness that makes a non-canonical encoding expressible.
 */
function smallXPoint(c: Curve): { x: bigint; y: bigint } {
  const limit = 1n << BigInt(c.bytes * 8);
  for (let x = 1n; x < 100000n; x++) {
    if (x + c.p >= limit) break;
    const y = sqrtMod(rhs(c, x), c.p);
    if (y !== null) return { x, y };
  }
  throw new Error(`no small-x point found for ${c.openssl}`);
}

// --- root-finding for the y-side witness ------------------------------------
//
// Polynomials over F_p as little-endian coefficient arrays. Only enough to run
// gcd(x^p − x, f) for a cubic f, which yields f's distinct roots.

type Poly = bigint[];

function polyTrim(a: Poly, p: bigint): Poly {
  const r = a.map((v) => mod(v, p));
  while (r.length > 0 && r[r.length - 1] === 0n) r.pop();
  return r;
}

function polyMul(a: Poly, b: Poly, p: bigint): Poly {
  if (a.length === 0 || b.length === 0) return [];
  const out = new Array<bigint>(a.length + b.length - 1).fill(0n);
  for (let i = 0; i < a.length; i++)
    for (let j = 0; j < b.length; j++)
      out[i + j] = mod(out[i + j]! + a[i]! * b[j]!, p);
  return polyTrim(out, p);
}

/** Remainder of `a` divided by monic-izable `b`. */
function polyMod(a: Poly, b: Poly, p: bigint): Poly {
  const r = polyTrim([...a], p);
  const d = polyTrim([...b], p);
  if (d.length === 0) throw new Error('divide by zero polynomial');
  const invLead = powm(d[d.length - 1]!, p - 2n, p);
  while (r.length >= d.length) {
    const shift = r.length - d.length;
    const f = mod(r[r.length - 1]! * invLead, p);
    for (let i = 0; i < d.length; i++)
      r[shift + i] = mod(r[shift + i]! - f * d[i]!, p);
    while (r.length > 0 && mod(r[r.length - 1]!, p) === 0n) r.pop();
  }
  return polyTrim(r, p);
}

function polySub(a: Poly, b: Poly, p: bigint): Poly {
  const out: Poly = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++)
    out.push(mod((a[i] ?? 0n) - (b[i] ?? 0n), p));
  return polyTrim(out, p);
}

/** base^e mod m, over F_p[X]. */
function polyPowMod(base: Poly, e: bigint, m: Poly, p: bigint): Poly {
  let acc: Poly = [1n];
  let b = polyMod(base, m, p);
  let k = e;
  while (k > 0n) {
    if (k & 1n) acc = polyMod(polyMul(acc, b, p), m, p);
    b = polyMod(polyMul(b, b, p), m, p);
    k >>= 1n;
  }
  return acc;
}

function polyGcd(a: Poly, b: Poly, p: bigint): Poly {
  let u = polyTrim([...a], p);
  let v = polyTrim([...b], p);
  while (v.length > 0) {
    const t = polyMod(u, v, p);
    u = v;
    v = t;
  }
  // normalise to monic
  if (u.length === 0) return u;
  const inv = powm(u[u.length - 1]!, p - 2n, p);
  return u.map((v2) => mod(v2 * inv, p));
}

/**
 * One root of `f` in F_p, or null. gcd(X^p − X, f) is the product of f's
 * distinct linear factors; Cantor–Zassenhaus then splits that down to a single
 * factor when there is more than one root (which is the usual case on
 * secp256k1, where p ≡ 1 mod 3 makes the cubic X³ − (y² − b) have either three
 * roots or none).
 */
function anyRoot(f: Poly, p: bigint): bigint | null {
  let g = polyGcd(f, polySub(polyPowMod([0n, 1n], p, f, p), [0n, 1n], p), p);
  if (g.length < 2) return null;
  for (let guard = 0; g.length > 2 && guard < 64; guard++) {
    for (let d = 1n; d < 64n; d++) {
      const h = polyGcd(g, polySub(polyPowMod([d, 1n], (p - 1n) / 2n, g, p), [1n], p), p);
      if (h.length >= 2 && h.length < g.length) { g = h; break; }
    }
  }
  return g.length === 2 ? mod(-g[0]!, p) : null;
}

/**
 * A curve point with a SMALL y — the witness the old comment declared
 * unconstructible. Fix y, and x is a root of the cubic
 * f(X) = X³ + a·X + (b − y²) over F_p, found algebraically in milliseconds.
 * No 2^32 search, on any of the three curves.
 */
function smallYPoint(c: Curve): { x: bigint; y: bigint } {
  const limit = 1n << BigInt(c.bytes * 8);
  for (let y = 1n; y < 200n; y++) {
    if (y + c.p >= limit) break;
    const f: Poly = polyTrim([mod(c.b - y * y, c.p), mod(c.a, c.p), 0n, 1n], c.p);
    const x = anyRoot(f, c.p);
    if (x !== null && isOnCurve(c, x, y)) return { x, y };
  }
  throw new Error(`no small-y point found for ${c.openssl}`);
}

// --- harness ----------------------------------------------------------------

const blob = (hex: string) => Uint8Array.from(Buffer.from(hex, 'hex'));

function exec(ops: StackOp[]): string {
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  const r = new ScriptVM().executeHex(scriptHex) as never as { stack: Uint8Array[] };
  return r.stack.length ? Buffer.from(r.stack[r.stack.length - 1]!).toString('hex') : '(empty)';
}

/** Run the curve's on-curve emitter over a raw point blob. */
function onCurve(c: Curve, pointHex: string): boolean {
  const ops: StackOp[] = [{ op: 'push', value: blob(pointHex) } as StackOp];
  c.emitOnCurve((o: StackOp) => ops.push(o));
  const top = exec(ops);
  // Script booleans: '' / '00' are false, anything else true.
  return top !== '(empty)' && top !== '' && top !== '00';
}

function add(c: Curve, aHex: string, bHex: string): string {
  const ops: StackOp[] = [
    { op: 'push', value: blob(aHex) } as StackOp,
    { op: 'push', value: blob(bHex) } as StackOp,
  ];
  c.emitAdd((o: StackOp) => ops.push(o));
  return exec(ops);
}

/** Did the adder ABORT? `exec` above reports only the stack, not the error. */
function addAborted(c: Curve, aHex: string, bHex: string): boolean {
  const ops: StackOp[] = [
    { op: 'push', value: blob(aHex) } as StackOp,
    { op: 'push', value: blob(bHex) } as StackOp,
  ];
  c.emitAdd((o: StackOp) => ops.push(o));
  const { scriptHex } = emitMethod({ name: 't', ops } as never) as { scriptHex: string };
  return (new ScriptVM().executeHex(scriptHex) as never as { error?: unknown }).error !== undefined;
}

/**
 * OpenSSL's verdict on an uncompressed point: on-curve AND canonical.
 * `ECDH.convertKey` parses 04‖x‖y through OpenSSL's `EC_POINT_oct2point`,
 * which rejects both off-curve points and out-of-range field elements.
 */
function opensslAcceptsPoint(c: Curve, pointHex: string): boolean {
  try {
    ECDH.convertKey('04' + pointHex, c.openssl, 'hex', 'hex', 'compressed');
    return true;
  } catch {
    return false;
  }
}

for (const [name, c] of Object.entries(CURVES) as Array<[string, Curve]>) {
  const w = c.bytes * 2;
  const hx = (v: bigint) => v.toString(16).padStart(w, '0');

  describe(`${name} on-curve canonicity (GAP-301)`, () => {
    const P = smallXPoint(c);
    const canonical = hx(P.x) + hx(P.y);
    const nonCanonicalX = hx(P.x + c.p) + hx(P.y);

    it('the witness is a genuine curve point with an expressible non-canonical x', () => {
      expect(isOnCurve(c, P.x, P.y)).toBe(true);
      expect(P.x + c.p).toBeLessThan(1n << BigInt(c.bytes * 8));
      // Same field element, different bytes — the whole point of the test.
      expect(mod(P.x + c.p, c.p)).toBe(P.x);
      expect(nonCanonicalX).not.toBe(canonical);
    });

    it('oracle: OpenSSL accepts the canonical encoding and rejects x ≥ p', () => {
      expect(opensslAcceptsPoint(c, canonical)).toBe(true);
      expect(opensslAcceptsPoint(c, nonCanonicalX)).toBe(false);
    });

    it('accepts the canonical point', () => {
      expect(onCurve(c, canonical)).toBe(true);
    });

    it('rejects x ≥ p — agreeing with OpenSSL', () => {
      expect(onCurve(c, nonCanonicalX)).toBe(false);
    });

    it('still rejects a point that is off the curve outright', () => {
      const offCurve = hx(P.x + 1n) + hx(P.y);
      expect(opensslAcceptsPoint(c, offCurve)).toBe(false);
      expect(onCurve(c, offCurve)).toBe(false);
    });

    // Why the guard is load-bearing rather than cosmetic: the two encodings
    // denote the same group element, but `emitAdd` compares the RAW x values
    // to detect doubling, so it takes the chord path and divides by zero.
    //
    // R-117 CLOSED THE OTHER HALF OF THIS, and the history is the point. This
    // very test recorded, as the JUSTIFICATION for the predicate guard, that
    // `add(P, P′)` returned an off-curve blob from a SUCCEEDING script and that
    // “only the on-curve gate can reject the input”. That was true, and it left
    // every caller who did not write the gate holding a wrong answer with no
    // error channel — a documented defect standing in the value builtins
    // because the predicate could paper over it. `ecAdd` / `ecMul` / `ecNegate`
    // and their P-256 / P-384 twins now VERIFY that both coordinates are field
    // elements and abort otherwise, so the adder never reaches the chord path
    // on a non-canonical operand at all.
    //
    // The predicate guard is still load-bearing, and still tested above: it is
    // what lets `if (ecOnCurve(p))` answer “no” instead of killing the script.
    it('the gate is load-bearing: add(P, P′) is REJECTED (it used to return an off-curve blob)', () => {
      expect(addAborted(c, canonical, nonCanonicalX)).toBe(true);
      expect(addAborted(c, nonCanonicalX, canonical)).toBe(true);

      // CONTROL — the canonical double still computes, and is on the curve.
      // Without this, a gate that rejected EVERYTHING would pass the line above.
      expect(addAborted(c, canonical, canonical)).toBe(false);
      const two = add(c, canonical, canonical);
      expect(two).not.toBe('(empty)');
      expect(isOnCurve(c, BigInt('0x' + two.slice(0, w)), BigInt('0x' + two.slice(w)))).toBe(true);
    });

    if (c.alreadyGuarded) {
      it('control: this curve was already guarded before GAP-301', () => {
        expect(c.alreadyGuarded).toBe(true);
      });
    }
  });

  // The y half of the guard, with a real witness rather than an assumption.
  describe(`${name} on-curve canonicity — the y half`, () => {
    const Q = smallYPoint(c);
    const canonicalY = hx(Q.x) + hx(Q.y);
    const nonCanonicalY = hx(Q.x) + hx(Q.y + c.p);

    it('a small-y curve point exists and its y ≥ p encoding fits the width', () => {
      expect(isOnCurve(c, Q.x, Q.y)).toBe(true);
      expect(Q.y + c.p).toBeLessThan(1n << BigInt(c.bytes * 8));
      expect(mod(Q.y + c.p, c.p)).toBe(Q.y);
    });

    it('oracle: OpenSSL accepts the canonical encoding and rejects y ≥ p', () => {
      expect(opensslAcceptsPoint(c, canonicalY)).toBe(true);
      expect(opensslAcceptsPoint(c, nonCanonicalY)).toBe(false);
    });

    it('accepts the canonical point, rejects y ≥ p — agreeing with OpenSSL', () => {
      expect(onCurve(c, canonicalY)).toBe(true);
      expect(onCurve(c, nonCanonicalY)).toBe(false);
    });
  });
}
