import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * P256EncodeNegate at the EXAMPLES layer — the interpreter half of the oracle.
 *
 * `conformance/p256_p384_encode_negate_execution_test.go` spends this
 * contract's compiled bytes on the go-sdk consensus interpreter. This file
 * reads the same source through the ANF interpreter, against curve arithmetic
 * written here in plain BigInt from the NIST parameters — a third
 * implementation, independent of both the compiler and the Go test.
 *
 * The rows that matter are the compression parities. CL-BUG-095 was a parity
 * bit read from the wrong byte, which made the same point compress to 02‖x or
 * 03‖x at the caller's choice and made anything hashing a compressed pubkey
 * forgeable between the two spellings. Every accept below is paired with the
 * opposite-prefix reject.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'P256EncodeNegate.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

// --- P-256 in BigInt, from the NIST parameters -------------------------------
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const COORD_BYTES = 32;

const mod = (a: bigint) => ((a % P) + P) % P;
const inv = (a: bigint) => {
  let [old, r] = [P, mod(a)];
  let [x0, x1] = [0n, 1n];
  while (r !== 0n) {
    const q = old / r;
    [old, r] = [r, old - q * r];
    [x0, x1] = [x1, x0 - q * x1];
  }
  return mod(x0);
};

type Pt = { x: bigint; y: bigint };

/** Short-Weierstrass addition for y^2 = x^3 - 3x + b. */
function add(a: Pt, b: Pt): Pt {
  const lam = a.x === b.x
    ? mod((3n * a.x * a.x - 3n) * inv(2n * a.y))
    : mod((b.y - a.y) * inv(b.x - a.x));
  const x = mod(lam * lam - a.x - b.x);
  return { x, y: mod(lam * (a.x - x) - a.y) };
}

function mul(k: bigint, p: Pt): Pt {
  let acc = p;
  let r: Pt | null = null;
  while (k > 0n) {
    if (k & 1n) r = r === null ? acc : add(r, acc);
    acc = add(acc, acc);
    k >>= 1n;
  }
  if (r === null) throw new Error('k must be positive');
  return r;
}

const coord = (v: bigint) => v.toString(16).padStart(COORD_BYTES * 2, '0');
const blob = (p: Pt) => coord(p.x) + coord(p.y);
const compress = (p: Pt) => (p.y % 2n === 0n ? '02' : '03') + coord(p.x);
const negate = (p: Pt): Pt => ({ x: p.x, y: mod(P - p.y) });
const flip = (c: string) => (c.slice(0, 2) === '02' ? '03' : '02') + c.slice(2);

const G: Pt = { x: GX, y: GY };
const Q = mul(0x1234567890abcdefn, G);
const NEG_G = negate(G);
const ZERO = coord(0n);

/** A contract with compress(negate(G)) baked in. */
function contract(expectedCompressed = compress(NEG_G)) {
  return TestContract.fromSource(source, { expectedCompressed }, FILE);
}

describe('P256EncodeNegate — negate', () => {
  it('negates G', () => {
    const r = contract().call('checkNegate', { p: blob(G), expected: blob(NEG_G) });
    expect(r.success, r.error).toBe(true);
  });

  it('negates a derived point', () => {
    const r = contract().call('checkNegate', { p: blob(Q), expected: blob(negate(Q)) });
    expect(r.success, r.error).toBe(true);
  });

  it('is an involution', () => {
    const r = contract().call('checkNegate', { p: blob(NEG_G), expected: blob(G) });
    expect(r.success, r.error).toBe(true);
  });

  it('reduces y = 0 back to 0, not to p', () => {
    // p - 0 is p, which is NOT a field element. A negate that forgot to reduce
    // would hand every downstream canonicity check a value outside the field.
    const input = coord(GX) + ZERO;
    expect(contract().call('checkNegate', { p: input, expected: input }).success).toBe(true);
    expect(contract().call('checkNegate', { p: input, expected: coord(GX) + coord(P) }).success)
      .toBe(false);
  });

  it('is not the identity', () => {
    expect(contract().call('checkNegate', { p: blob(G), expected: blob(G) }).success)
      .toBe(false);
  });
});

describe('P256EncodeNegate — encodeCompressed', () => {
  // G and -G have opposite y parity by construction, so running both proves
  // the prefix tracks the parity rather than being a constant.
  it('G and -G take different prefixes', () => {
    expect(compress(G).slice(0, 2)).not.toBe(compress(NEG_G).slice(0, 2));
  });

  it.each<[string, () => Pt]>([
    ['G', () => G],
    ['-G', () => NEG_G],
    ['a derived point', () => Q],
    ['the negation of a derived point', () => negate(Q)],
  ])('compresses %s', (_name, pt) => {
    const p = pt();
    const r = contract().call('checkEncode', { p: blob(p), expected: compress(p) });
    expect(r.success, r.error).toBe(true);
  });

  it.each<[string, () => Pt]>([
    ['G', () => G],
    ['-G', () => NEG_G],
  ])('rejects the opposite prefix for %s', (_name, pt) => {
    const p = pt();
    expect(contract().call('checkEncode', { p: blob(p), expected: flip(compress(p)) }).success)
      .toBe(false);
  });
});

describe('P256EncodeNegate — negate then encode', () => {
  it('matches the baked compress(-G)', () => {
    const r = contract().call('checkNegateThenEncode', { p: blob(G) });
    expect(r.success, r.error).toBe(true);
  });

  it('does not match compress(G) — the negation is not a no-op', () => {
    const r = contract(compress(G)).call('checkNegateThenEncode', { p: blob(G) });
    expect(r.success).toBe(false);
  });
});
