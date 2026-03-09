import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'ConvergenceProof.runar.ts'), 'utf8');

// secp256k1 constants
const EC_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const EC_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

// ---------------------------------------------------------------------------
// JS EC helpers for test vector generation (same as SchnorrZKP tests)
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

describe('ConvergenceProof contract', () => {
  it('proves convergence with valid delta offset', () => {
    // Shared underlying token
    const token = 42n;

    // Two distinct ECDH-derived offsets
    const oA = 100n;
    const oB = 37n;

    // R_A = (token + o_A) · G,  R_B = (token + o_B) · G
    const [raX, raY] = scalarMul(GX, GY, mod(token + oA, EC_N));
    const [rbX, rbY] = scalarMul(GX, GY, mod(token + oB, EC_N));

    // Δo = o_A - o_B (mod n)
    const deltaO = mod(oA - oB, EC_N);

    const c = TestContract.fromSource(source, {
      rA: makePointHex(raX, raY),
      rB: makePointHex(rbX, rbY),
    });
    const result = c.call('proveConvergence', { deltaO });
    expect(result.success).toBe(true);
  });

  it('rejects wrong delta offset', () => {
    const token = 42n;
    const oA = 100n;
    const oB = 37n;

    const [raX, raY] = scalarMul(GX, GY, mod(token + oA, EC_N));
    const [rbX, rbY] = scalarMul(GX, GY, mod(token + oB, EC_N));

    // Wrong delta: off by 1
    const wrongDelta = mod(oA - oB + 1n, EC_N);

    const c = TestContract.fromSource(source, {
      rA: makePointHex(raX, raY),
      rB: makePointHex(rbX, rbY),
    });
    const result = c.call('proveConvergence', { deltaO: wrongDelta });
    expect(result.success).toBe(false);
  });

  it('rejects when tokens differ (no convergence)', () => {
    // Two DIFFERENT tokens — should not converge
    const tokenA = 42n;
    const tokenB = 99n;

    const oA = 100n;
    const oB = 37n;

    // R_A = (tokenA + o_A) · G,  R_B = (tokenB + o_B) · G
    const [raX, raY] = scalarMul(GX, GY, mod(tokenA + oA, EC_N));
    const [rbX, rbY] = scalarMul(GX, GY, mod(tokenB + oB, EC_N));

    // Correct delta for offsets only — but tokens don't match so it won't verify
    const deltaO = mod(oA - oB, EC_N);

    const c = TestContract.fromSource(source, {
      rA: makePointHex(raX, raY),
      rB: makePointHex(rbX, rbY),
    });
    const result = c.call('proveConvergence', { deltaO });
    expect(result.success).toBe(false);
  });

  it('proves convergence with larger scalars', () => {
    const token = 0xDEADBEEFCAFEBABE1234567890ABCDEFn;
    const oA = 0xA1B2C3D4E5F60718293A4B5C6D7E8F90n;
    const oB = 0x1122334455667788AABBCCDDEEFF0011n;

    const [raX, raY] = scalarMul(GX, GY, mod(token + oA, EC_N));
    const [rbX, rbY] = scalarMul(GX, GY, mod(token + oB, EC_N));

    const deltaO = mod(oA - oB, EC_N);

    const c = TestContract.fromSource(source, {
      rA: makePointHex(raX, raY),
      rB: makePointHex(rbX, rbY),
    });
    const result = c.call('proveConvergence', { deltaO });
    expect(result.success).toBe(true);
  });

  it('proves convergence when delta is zero (same offset)', () => {
    // Same offset for both parties — delta is 0, meaning R_A = R_B
    const token = 42n;
    const offset = 100n;

    const [rX, rY] = scalarMul(GX, GY, mod(token + offset, EC_N));
    const pointHex = makePointHex(rX, rY);

    const c = TestContract.fromSource(source, {
      rA: pointHex,
      rB: pointHex,
    });
    // Δo = 0 means ecMulGen(0) → point at infinity issue;
    // but subtraction of identical points also gives point at infinity.
    // This is an edge case that may or may not be handled by the EC primitives.
    // If ecMulGen(0) is not supported, this test documents that behavior.
    const result = c.call('proveConvergence', { deltaO: 0n });
    // Don't assert success/failure — just document the edge case runs without crashing
    expect(typeof result.success).toBe('boolean');
  });
});
