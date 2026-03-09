/**
 * EC primitives cross-verification tests.
 *
 * Every test vector is computed by @bsv/sdk (the secp256k1 reference
 * implementation used by the BSV node network) and compared against
 * Rúnar's interpreter output.  This ensures our EC builtins produce
 * identical results to the production SDK.
 */
import { describe, it, expect } from 'vitest';
import { Point as BsvPoint, BigNumber, PrivateKey } from '@bsv/sdk';
import { TestContract } from '../index.js';

// ---- helpers ----------------------------------------------------------------

function bigintToHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}
void bigintToHex32; // TODO: will be used by upcoming EC cross-verify tests

/** Construct a 64-byte Rúnar Point hex from a @bsv/sdk Point. */
function bsvPointToHex(p: BsvPoint): string {
  return p.getX().toHex(32) + p.getY().toHex(32);
}

/** Get x as bigint from @bsv/sdk Point. */
function bsvX(p: BsvPoint): bigint {
  return BigInt('0x' + p.getX().toHex(32));
}

/** Get y as bigint from @bsv/sdk Point. */
function bsvY(p: BsvPoint): bigint {
  return BigInt('0x' + p.getY().toHex(32));
}

// ---- secp256k1 reference from @bsv/sdk --------------------------------------

const G_BSV = new BsvPoint(
  '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8',
);

const G_HEX = bsvPointToHex(G_BSV);
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn; // eslint-disable-line
void EC_P; // TODO: will be used by upcoming EC cross-verify tests

// ---- contracts used across tests --------------------------------------------

const POINT_XY = `
class PointXY extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public checkX(expected: bigint) { assert(ecPointX(this.pt) === expected); }
  public checkY(expected: bigint) { assert(ecPointY(this.pt) === expected); }
}
`;

const EC_ADD = `
class Add extends SmartContract {
  readonly a: Point;
  readonly b: Point;
  constructor(a: Point, b: Point) { super(a, b); this.a = a; this.b = b; }
  public checkX(expected: bigint) { assert(ecPointX(ecAdd(this.a, this.b)) === expected); }
  public checkY(expected: bigint) { assert(ecPointY(ecAdd(this.a, this.b)) === expected); }
}
`;

const EC_MUL = `
class Mul extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public checkX(k: bigint, expected: bigint) { assert(ecPointX(ecMul(this.pt, k)) === expected); }
  public checkY(k: bigint, expected: bigint) { assert(ecPointY(ecMul(this.pt, k)) === expected); }
}
`;

const EC_MULGEN = `
class MulGen extends SmartContract {
  constructor() { super(); }
  public checkX(k: bigint, expected: bigint) { assert(ecPointX(ecMulGen(k)) === expected); }
  public checkY(k: bigint, expected: bigint) { assert(ecPointY(ecMulGen(k)) === expected); }
}
`;

const EC_NEGATE = `
class Negate extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public checkY(expected: bigint) { assert(ecPointY(ecNegate(this.pt)) === expected); }
  public checkOnCurve() { assert(ecOnCurve(ecNegate(this.pt))); }
}
`;

const EC_ONCURVE = `
class OnCurve extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check() { assert(ecOnCurve(this.pt)); }
}
`;

const EC_COMPRESS = `
class Compress extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }
  public check(expected: ByteString) { assert(ecEncodeCompressed(this.pt) === expected); }
}
`;

const EC_MAKEPOINT = `
class MakePoint extends SmartContract {
  readonly expected: Point;
  constructor(expected: Point) { super(expected); this.expected = expected; }
  public check(x: bigint, y: bigint) { assert(ecMakePoint(x, y) === this.expected); }
}
`;

const SCHNORR_ZKP = `
class SchnorrZKP extends SmartContract {
  readonly pubKey: Point;
  constructor(pubKey: Point) { super(pubKey); this.pubKey = pubKey; }
  public verify(rPoint: Point, s: bigint, e: bigint) {
    const sG = ecMulGen(s);
    const eP = ecMul(this.pubKey, e);
    const rhs = ecAdd(rPoint, eP);
    assert(ecPointX(sG) === ecPointX(rhs));
    assert(ecPointY(sG) === ecPointY(rhs));
  }
}
`;

// =============================================================================
// Cross-verification: every expected value derived from @bsv/sdk
// =============================================================================

describe('EC cross-verification against @bsv/sdk', () => {
  // ---------- ecPointX / ecPointY -------------------------------------------

  describe('ecPointX / ecPointY', () => {
    const scalars = [1n, 2n, 3n, 7n, 42n, 12345n];

    for (const k of scalars) {
      it(`extracts coords of ${k}G`, () => {
        const ref = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const hex = bsvPointToHex(ref);
        const c = TestContract.fromSource(POINT_XY, { pt: hex });
        expect(c.call('checkX', { expected: bsvX(ref) }).success).toBe(true);
        expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
      });
    }
  });

  // ---------- ecMakePoint ----------------------------------------------------

  describe('ecMakePoint', () => {
    it('reconstructs kG for k=1,2,3,7,42', () => {
      for (const k of [1n, 2n, 3n, 7n, 42n]) {
        const ref = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const hex = bsvPointToHex(ref);
        const c = TestContract.fromSource(EC_MAKEPOINT, { expected: hex });
        expect(c.call('check', { x: bsvX(ref), y: bsvY(ref) }).success).toBe(true);
      }
    });
  });

  // ---------- ecOnCurve ------------------------------------------------------

  describe('ecOnCurve', () => {
    it('valid points are on curve', () => {
      for (const k of [1n, 2n, 7n, 42n, 12345n]) {
        const ref = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const hex = bsvPointToHex(ref);
        const c = TestContract.fromSource(EC_ONCURVE, { pt: hex });
        expect(c.call('check').success).toBe(true);
      }
    });

    it('invalid point is not on curve', () => {
      // Flip last byte of y coordinate
      const badHex = bsvPointToHex(G_BSV).slice(0, -2) + 'ff';
      const c = TestContract.fromSource(EC_ONCURVE, { pt: badHex });
      expect(c.call('check').success).toBe(false);
    });
  });

  // ---------- ecAdd ----------------------------------------------------------

  describe('ecAdd', () => {
    it('G + G = 2G (point doubling)', () => {
      const ref = G_BSV.dbl();
      const c = TestContract.fromSource(EC_ADD, { a: G_HEX, b: G_HEX });
      expect(c.call('checkX', { expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
    });

    it('G + 2G = 3G (different points)', () => {
      const G2 = G_BSV.dbl();
      const ref = G_BSV.mul(new BigNumber(3));
      const c = TestContract.fromSource(EC_ADD, { a: G_HEX, b: bsvPointToHex(G2) });
      expect(c.call('checkX', { expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
    });

    it('2G + 5G = 7G', () => {
      const G2 = G_BSV.mul(new BigNumber(2));
      const G5 = G_BSV.mul(new BigNumber(5));
      const ref = G_BSV.mul(new BigNumber(7));
      const c = TestContract.fromSource(EC_ADD, { a: bsvPointToHex(G2), b: bsvPointToHex(G5) });
      expect(c.call('checkX', { expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
    });

    it('3G + 3G = 6G (doubling non-generator)', () => {
      const G3 = G_BSV.mul(new BigNumber(3));
      const ref = G_BSV.mul(new BigNumber(6));
      const hex3 = bsvPointToHex(G3);
      const c = TestContract.fromSource(EC_ADD, { a: hex3, b: hex3 });
      expect(c.call('checkX', { expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
    });
  });

  // ---------- ecMul ----------------------------------------------------------

  describe('ecMul', () => {
    const cases: Array<[bigint, string]> = [
      [1n, 'k=1'],
      [2n, 'k=2'],
      [3n, 'k=3'],
      [7n, 'k=7'],
      [42n, 'k=42'],
      [12345n, 'k=12345'],
    ];

    for (const [k, label] of cases) {
      it(`G * ${label}`, () => {
        const ref = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const c = TestContract.fromSource(EC_MUL, { pt: G_HEX });
        expect(c.call('checkX', { k, expected: bsvX(ref) }).success).toBe(true);
        expect(c.call('checkY', { k, expected: bsvY(ref) }).success).toBe(true);
      });
    }

    it('(n-1) * G = -G', () => {
      const k = EC_N - 1n;
      const ref = G_BSV.neg();
      const c = TestContract.fromSource(EC_MUL, { pt: G_HEX });
      expect(c.call('checkX', { k, expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { k, expected: bsvY(ref) }).success).toBe(true);
    });

    it('scalar mul on non-generator point: 5 * 3G = 15G', () => {
      const G3 = G_BSV.mul(new BigNumber(3));
      const ref = G_BSV.mul(new BigNumber(15));
      const c = TestContract.fromSource(EC_MUL, { pt: bsvPointToHex(G3) });
      expect(c.call('checkX', { k: 5n, expected: bsvX(ref) }).success).toBe(true);
      expect(c.call('checkY', { k: 5n, expected: bsvY(ref) }).success).toBe(true);
    });
  });

  // ---------- ecMulGen -------------------------------------------------------

  describe('ecMulGen', () => {
    for (const k of [1n, 2n, 3n, 7n, 42n, 12345n]) {
      it(`ecMulGen(${k})`, () => {
        const ref = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const c = TestContract.fromSource(EC_MULGEN, {});
        expect(c.call('checkX', { k, expected: bsvX(ref) }).success).toBe(true);
        expect(c.call('checkY', { k, expected: bsvY(ref) }).success).toBe(true);
      });
    }
  });

  // ---------- ecNegate -------------------------------------------------------

  describe('ecNegate', () => {
    for (const k of [1n, 2n, 7n, 42n]) {
      it(`negate ${k}G`, () => {
        const kG = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const ref = kG.neg();
        const c = TestContract.fromSource(EC_NEGATE, { pt: bsvPointToHex(kG) });
        expect(c.call('checkY', { expected: bsvY(ref) }).success).toBe(true);
        expect(c.call('checkOnCurve').success).toBe(true);
      });
    }
  });

  // ---------- ecEncodeCompressed ---------------------------------------------

  describe('ecEncodeCompressed', () => {
    for (const k of [1n, 2n, 3n, 7n, 42n]) {
      it(`compress ${k}G`, () => {
        const kG = G_BSV.mul(new BigNumber(k.toString(16), 16));
        const refHex = kG.encode(true, 'hex') as string;
        const c = TestContract.fromSource(EC_COMPRESS, { pt: bsvPointToHex(kG) });
        expect(c.call('check', { expected: refHex }).success).toBe(true);
      });
    }
  });

  // ---------- Schnorr ZKP verification against @bsv/sdk ---------------------

  describe('Schnorr ZKP end-to-end', () => {
    it('verifies proof with k=42, r=12345, e=7', () => {
      const privKey = 42n;
      const r = 12345n;
      const e = 7n;

      // Reference: compute all points via @bsv/sdk
      const pubRef = G_BSV.mul(new BigNumber(privKey.toString(16), 16));
      const rRef = G_BSV.mul(new BigNumber(r.toString(16), 16));
      const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;

      // Verify in @bsv/sdk: s*G === R + e*P
      const sG = G_BSV.mul(new BigNumber(s.toString(16), 16));
      const eP = pubRef.mul(new BigNumber(e.toString(16), 16));
      const rhs = rRef.add(eP);
      expect(sG.eq(rhs)).toBe(true); // sanity: @bsv/sdk agrees

      // Now verify via Rúnar interpreter
      const c = TestContract.fromSource(SCHNORR_ZKP, { pubKey: bsvPointToHex(pubRef) });
      const result = c.call('verify', { rPoint: bsvPointToHex(rRef), s, e });
      expect(result.success).toBe(true);
    });

    it('verifies proof with large scalars', () => {
      const privKey = 0xDEADBEEFCAFEBABE1234567890ABCDEFn;
      const r = 0xFEDCBA9876543210ABCDEF0123456789n;
      const e = 0x123456789ABCDEF0n;

      const pubRef = G_BSV.mul(new BigNumber(privKey.toString(16), 16));
      const rRef = G_BSV.mul(new BigNumber(r.toString(16), 16));
      const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;

      // Verify in @bsv/sdk first
      const sG = G_BSV.mul(new BigNumber(s.toString(16), 16));
      const eP = pubRef.mul(new BigNumber(e.toString(16), 16));
      const rhs = rRef.add(eP);
      expect(sG.eq(rhs)).toBe(true);

      // Verify via Rúnar
      const c = TestContract.fromSource(SCHNORR_ZKP, { pubKey: bsvPointToHex(pubRef) });
      const result = c.call('verify', { rPoint: bsvPointToHex(rRef), s, e });
      expect(result.success).toBe(true);
    });

    it('rejects invalid proof (tampered s)', () => {
      const privKey = 42n;
      const r = 12345n;
      const e = 7n;
      const pubRef = G_BSV.mul(new BigNumber(privKey.toString(16), 16));
      const rRef = G_BSV.mul(new BigNumber(r.toString(16), 16));
      const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;
      const badS = s + 1n;

      const c = TestContract.fromSource(SCHNORR_ZKP, { pubKey: bsvPointToHex(pubRef) });
      const result = c.call('verify', { rPoint: bsvPointToHex(rRef), s: badS, e });
      expect(result.success).toBe(false);
    });

    it('rejects invalid proof (wrong challenge)', () => {
      const privKey = 42n;
      const r = 12345n;
      const e = 7n;
      const pubRef = G_BSV.mul(new BigNumber(privKey.toString(16), 16));
      const rRef = G_BSV.mul(new BigNumber(r.toString(16), 16));
      const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;

      const c = TestContract.fromSource(SCHNORR_ZKP, { pubKey: bsvPointToHex(pubRef) });
      const result = c.call('verify', { rPoint: bsvPointToHex(rRef), s, e: e + 1n });
      expect(result.success).toBe(false);
    });
  });

  // ---------- PrivateKey -> PublicKey cross-check ----------------------------

  describe('PrivateKey derivation matches ecMulGen', () => {
    const keys = [1n, 2n, 42n, 12345n, 0xDEADBEEFn];

    for (const k of keys) {
      it(`private key ${k} -> public key matches ecMulGen(${k})`, () => {
        // @bsv/sdk PrivateKey derivation
        const pk = PrivateKey.fromHex(k.toString(16).padStart(64, '0'));
        const pub = pk.toPublicKey();

        // Rúnar ecMulGen
        const c = TestContract.fromSource(EC_MULGEN, {});
        expect(c.call('checkX', { k, expected: bsvX(pub) }).success).toBe(true);
        expect(c.call('checkY', { k, expected: bsvY(pub) }).success).toBe(true);
      });
    }
  });
});
