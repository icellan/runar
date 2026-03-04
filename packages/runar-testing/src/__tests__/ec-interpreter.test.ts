import { describe, it, expect } from 'vitest';
import { TestContract } from '../index.js';

// secp256k1 constants
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// Generator point as 64-byte hex (big-endian x || y)
const G_HEX =
  '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798' +
  '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';

// 2*G (known value)
const G2X = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5n;
const G2Y = 0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52An;

function bigintToHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0').toUpperCase();
}

// ---------------------------------------------------------------------------
// ecPointX / ecPointY
// ---------------------------------------------------------------------------

const POINT_XY_SOURCE = `
class PointXY extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }

  public checkX(expected: bigint) {
    assert(ecPointX(this.pt) === expected);
  }

  public checkY(expected: bigint) {
    assert(ecPointY(this.pt) === expected);
  }
}
`;

describe('ecPointX / ecPointY', () => {
  it('extracts x and y from generator point', () => {
    const c = TestContract.fromSource(POINT_XY_SOURCE, { pt: G_HEX });
    expect(c.call('checkX', { expected: GX }).success).toBe(true);
    expect(c.call('checkY', { expected: GY }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecMakePoint
// ---------------------------------------------------------------------------

const MAKE_POINT_SOURCE = `
class MakePoint extends SmartContract {
  readonly expected: Point;
  constructor(expected: Point) { super(expected); this.expected = expected; }

  public check(x: bigint, y: bigint) {
    assert(ecMakePoint(x, y) === this.expected);
  }
}
`;

describe('ecMakePoint', () => {
  it('constructs generator point from coordinates', () => {
    const c = TestContract.fromSource(MAKE_POINT_SOURCE, { expected: G_HEX });
    expect(c.call('check', { x: GX, y: GY }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecOnCurve
// ---------------------------------------------------------------------------

const ON_CURVE_SOURCE = `
class OnCurve extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }

  public check() {
    assert(ecOnCurve(this.pt));
  }
}
`;

describe('ecOnCurve', () => {
  it('generator point is on curve', () => {
    const c = TestContract.fromSource(ON_CURVE_SOURCE, { pt: G_HEX });
    expect(c.call('check').success).toBe(true);
  });

  it('random point is not on curve', () => {
    // Use G_x with wrong y
    const badPt = bigintToHex32(GX) + bigintToHex32(GY + 1n);
    const c = TestContract.fromSource(ON_CURVE_SOURCE, { pt: badPt });
    expect(c.call('check').success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ecNegate
// ---------------------------------------------------------------------------

const NEGATE_SOURCE = `
class Negate extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }

  public checkNegY(expected: bigint) {
    const neg = ecNegate(this.pt);
    assert(ecPointY(neg) === expected);
  }

  public checkNegOnCurve() {
    const neg = ecNegate(this.pt);
    assert(ecOnCurve(neg));
  }
}
`;

describe('ecNegate', () => {
  it('negated generator has y = p - Gy', () => {
    const c = TestContract.fromSource(NEGATE_SOURCE, { pt: G_HEX });
    const expectedNegY = EC_P - GY;
    expect(c.call('checkNegY', { expected: expectedNegY }).success).toBe(true);
  });

  it('negated point is still on curve', () => {
    const c = TestContract.fromSource(NEGATE_SOURCE, { pt: G_HEX });
    expect(c.call('checkNegOnCurve').success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecModReduce
// ---------------------------------------------------------------------------

const MOD_REDUCE_SOURCE = `
class ModReduce extends SmartContract {
  constructor() { super(); }

  public check(value: bigint, mod: bigint, expected: bigint) {
    assert(ecModReduce(value, mod) === expected);
  }
}
`;

describe('ecModReduce', () => {
  it('reduces positive value', () => {
    const c = TestContract.fromSource(MOD_REDUCE_SOURCE, {});
    expect(c.call('check', { value: 10n, mod: 7n, expected: 3n }).success).toBe(true);
  });

  it('reduces negative value to non-negative', () => {
    const c = TestContract.fromSource(MOD_REDUCE_SOURCE, {});
    expect(c.call('check', { value: -3n, mod: 7n, expected: 4n }).success).toBe(true);
  });

  it('reduces zero', () => {
    const c = TestContract.fromSource(MOD_REDUCE_SOURCE, {});
    expect(c.call('check', { value: 0n, mod: 7n, expected: 0n }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecAdd
// ---------------------------------------------------------------------------

const ADD_SOURCE = `
class Add extends SmartContract {
  readonly a: Point;
  readonly b: Point;
  constructor(a: Point, b: Point) { super(a, b); this.a = a; this.b = b; }

  public checkResultX(expected: bigint) {
    const r = ecAdd(this.a, this.b);
    assert(ecPointX(r) === expected);
  }

  public checkResultY(expected: bigint) {
    const r = ecAdd(this.a, this.b);
    assert(ecPointY(r) === expected);
  }
}
`;

describe('ecAdd', () => {
  it('G + G = 2G (via interpreter)', () => {
    const c = TestContract.fromSource(ADD_SOURCE, { a: G_HEX, b: G_HEX });
    // G + G is point doubling, should give 2G
    expect(c.call('checkResultX', { expected: G2X }).success).toBe(true);
    expect(c.call('checkResultY', { expected: G2Y }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecMul / ecMulGen
// ---------------------------------------------------------------------------

const MUL_SOURCE = `
class Mul extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }

  public checkMulX(k: bigint, expected: bigint) {
    const r = ecMul(this.pt, k);
    assert(ecPointX(r) === expected);
  }
}
`;

const MUL_GEN_SOURCE = `
class MulGen extends SmartContract {
  constructor() { super(); }

  public checkMulGenX(k: bigint, expected: bigint) {
    const r = ecMulGen(k);
    assert(ecPointX(r) === expected);
  }
}
`;

describe('ecMul', () => {
  it('G * 2 = 2G', () => {
    const c = TestContract.fromSource(MUL_SOURCE, { pt: G_HEX });
    expect(c.call('checkMulX', { k: 2n, expected: G2X }).success).toBe(true);
  });

  it('G * 1 = G', () => {
    const c = TestContract.fromSource(MUL_SOURCE, { pt: G_HEX });
    expect(c.call('checkMulX', { k: 1n, expected: GX }).success).toBe(true);
  });
});

describe('ecMulGen', () => {
  it('ecMulGen(1) = G', () => {
    const c = TestContract.fromSource(MUL_GEN_SOURCE, {});
    expect(c.call('checkMulGenX', { k: 1n, expected: GX }).success).toBe(true);
  });

  it('ecMulGen(2) = 2G', () => {
    const c = TestContract.fromSource(MUL_GEN_SOURCE, {});
    expect(c.call('checkMulGenX', { k: 2n, expected: G2X }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// ecEncodeCompressed
// ---------------------------------------------------------------------------

const ENCODE_SOURCE = `
class Encode extends SmartContract {
  readonly pt: Point;
  constructor(pt: Point) { super(pt); this.pt = pt; }

  public checkCompressed(expected: ByteString) {
    const compressed = ecEncodeCompressed(this.pt);
    assert(compressed === expected);
  }
}
`;

describe('ecEncodeCompressed', () => {
  it('compresses generator point correctly', () => {
    // G has even y (last byte 0xB8, which is even), so prefix = 02
    const expectedHex = '02' + bigintToHex32(GX);
    const c = TestContract.fromSource(ENCODE_SOURCE, { pt: G_HEX });
    expect(c.call('checkCompressed', { expected: expectedHex }).success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Schnorr ZKP verifier (integration test using interpreter)
// ---------------------------------------------------------------------------

const SCHNORR_ZKP_SOURCE = `
class SchnorrZKP extends SmartContract {
  readonly pubKey: Point;

  constructor(pubKey: Point) {
    super(pubKey);
    this.pubKey = pubKey;
  }

  public verify(rPoint: Point, s: bigint, e: bigint) {
    // Schnorr verification: s*G = R + e*P
    // Check: ecMulGen(s) === ecAdd(rPoint, ecMul(pubKey, e))
    const sG = ecMulGen(s);
    const eP = ecMul(this.pubKey, e);
    const rhs = ecAdd(rPoint, eP);
    assert(ecPointX(sG) === ecPointX(rhs));
    assert(ecPointY(sG) === ecPointY(rhs));
  }
}
`;

describe('Schnorr ZKP verifier (interpreter)', () => {
  it('verifies a valid Schnorr proof', () => {
    // Generate a proof: private key k, R = r*G, e = challenge, s = r + e*k mod n
    const privKey = 42n;
    const r = 12345n;

    // Compute pubKey = privKey * G via JS
    const pubKeyX = ecScalarMulX(GX, GY, privKey);
    const pubKeyY = ecScalarMulY(GX, GY, privKey);
    const pubKeyHex = bigintToHex32(pubKeyX) + bigintToHex32(pubKeyY);

    // R = r * G
    const rX = ecScalarMulX(GX, GY, r);
    const rY = ecScalarMulY(GX, GY, r);
    const rHex = bigintToHex32(rX) + bigintToHex32(rY);

    // Challenge e (normally hash of message+R, here we just pick a value)
    const e = 7n;

    // s = r + e * privKey mod n
    const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;

    const c = TestContract.fromSource(SCHNORR_ZKP_SOURCE, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e });
    expect(result.success).toBe(true);
  });

  it('rejects an invalid Schnorr proof', () => {
    const privKey = 42n;
    const r = 12345n;

    const pubKeyX = ecScalarMulX(GX, GY, privKey);
    const pubKeyY = ecScalarMulY(GX, GY, privKey);
    const pubKeyHex = bigintToHex32(pubKeyX) + bigintToHex32(pubKeyY);

    const rX = ecScalarMulX(GX, GY, r);
    const rY = ecScalarMulY(GX, GY, r);
    const rHex = bigintToHex32(rX) + bigintToHex32(rY);

    const e = 7n;
    const s = ((r + e * privKey) % EC_N + EC_N) % EC_N;

    // Tamper with s
    const badS = s + 1n;

    const c = TestContract.fromSource(SCHNORR_ZKP_SOURCE, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s: badS, e });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Helper: JS secp256k1 scalar multiplication for test vector generation
// ---------------------------------------------------------------------------

function ecMod(a: bigint, m: bigint): bigint {
  return ((a % m) + m) % m;
}

function ecModInv(a: bigint, m: bigint): bigint {
  let [old_r, r_val] = [ecMod(a, m), m];
  let [old_s, s_val] = [1n, 0n];
  while (r_val !== 0n) {
    const q = old_r / r_val;
    [old_r, r_val] = [r_val, old_r - q * r_val];
    [old_s, s_val] = [s_val, old_s - q * s_val];
  }
  return ecMod(old_s, m);
}

function ecPointAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] {
  const p = EC_P;
  if (x1 === x2 && y1 === y2) {
    const s = ecMod(3n * x1 * x1 * ecModInv(2n * y1, p), p);
    const rx = ecMod(s * s - 2n * x1, p);
    const ry = ecMod(s * (x1 - rx) - y1, p);
    return [rx, ry];
  }
  const s = ecMod((y2 - y1) * ecModInv(x2 - x1, p), p);
  const rx = ecMod(s * s - x1 - x2, p);
  const ry = ecMod(s * (x1 - rx) - y1, p);
  return [rx, ry];
}

function ecScalarMul(bx: bigint, by: bigint, k: bigint): [bigint, bigint] {
  k = ecMod(k, EC_N);
  let rx = bx;
  let ry = by;
  let started = false;
  for (let i = 255; i >= 0; i--) {
    if (started) [rx, ry] = ecPointAdd(rx, ry, rx, ry);
    if ((k >> BigInt(i)) & 1n) {
      if (!started) { rx = bx; ry = by; started = true; }
      else [rx, ry] = ecPointAdd(rx, ry, bx, by);
    }
  }
  return [rx, ry];
}

function ecScalarMulX(bx: bigint, by: bigint, k: bigint): bigint {
  return ecScalarMul(bx, by, k)[0];
}

function ecScalarMulY(bx: bigint, by: bigint, k: bigint): bigint {
  return ecScalarMul(bx, by, k)[1];
}
