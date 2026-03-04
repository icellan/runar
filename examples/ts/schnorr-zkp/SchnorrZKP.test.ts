import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'SchnorrZKP.runar.ts'), 'utf8');

// secp256k1 constants
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// ---------------------------------------------------------------------------
// JS EC helpers for test vector generation
// ---------------------------------------------------------------------------

function mod(a: bigint, m: bigint): bigint { return ((a % m) + m) % m; }

function modInv(a: bigint, m: bigint): bigint {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, m);
}

function pointAdd(x1: bigint, y1: bigint, x2: bigint, y2: bigint): [bigint, bigint] {
  if (x1 === x2 && y1 === y2) {
    const slope = mod(3n * x1 * x1 * modInv(2n * y1, EC_P), EC_P);
    const rx = mod(slope * slope - 2n * x1, EC_P);
    return [rx, mod(slope * (x1 - rx) - y1, EC_P)];
  }
  const slope = mod((y2 - y1) * modInv(x2 - x1, EC_P), EC_P);
  const rx = mod(slope * slope - x1 - x2, EC_P);
  return [rx, mod(slope * (x1 - rx) - y1, EC_P)];
}

function scalarMul(bx: bigint, by: bigint, k: bigint): [bigint, bigint] {
  k = mod(k, EC_N);
  let rx = bx, ry = by, started = false;
  for (let i = 255; i >= 0; i--) {
    if (started) [rx, ry] = pointAdd(rx, ry, rx, ry);
    if ((k >> BigInt(i)) & 1n) {
      if (!started) { rx = bx; ry = by; started = true; }
      else [rx, ry] = pointAdd(rx, ry, bx, by);
    }
  }
  return [rx, ry];
}

function bigintToHex32(n: bigint): string {
  return n.toString(16).padStart(64, '0').toUpperCase();
}

function makePointHex(x: bigint, y: bigint): string {
  return bigintToHex32(x) + bigintToHex32(y);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SchnorrZKP contract', () => {
  it('verifies a valid Schnorr ZKP proof', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 7n;
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e });
    expect(result.success).toBe(true);
  });

  it('rejects a proof with wrong s value', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 7n;
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s: s + 1n, e });
    expect(result.success).toBe(false);
  });

  it('rejects a proof with wrong challenge', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 7n;
    const s = mod(r + e * privKey, EC_N);

    // Use wrong challenge
    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e: e + 1n });
    expect(result.success).toBe(false);
  });

  it('works with larger private key', () => {
    const privKey = 0xDEADBEEFCAFEn;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 0xABCDEF0123456789n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = 0x42n;
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s, e });
    expect(result.success).toBe(true);
  });
});
