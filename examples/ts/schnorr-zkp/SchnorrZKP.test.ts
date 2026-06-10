import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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
// Fiat-Shamir helpers
// ---------------------------------------------------------------------------

function sha256(hex: string): string {
  return createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex').toUpperCase();
}

function hash256Hex(hex: string): string {
  return sha256(sha256(hex));
}

/** bin2num: interpret hex bytes as little-endian signed integer (Bitcoin script number). */
function bin2num(hex: string): bigint {
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length === 0) return 0n;
  const negative = (bytes[bytes.length - 1] & 0x80) !== 0;
  const last = bytes[bytes.length - 1] & 0x7f;
  let result = BigInt(last);
  for (let i = bytes.length - 2; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return negative ? -result : result;
}

/** Derive Fiat-Shamir challenge: e = bin2num(hash256(R || P)) */
function deriveChallenge(rHex: string, pubKeyHex: string): bigint {
  return bin2num(hash256Hex(rHex + pubKeyHex));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SchnorrZKP contract', () => {
  it('verifies a valid Schnorr ZKP proof with Fiat-Shamir challenge', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    // Challenge derived via Fiat-Shamir: e = bin2num(hash256(R || P))
    const e = deriveChallenge(rHex, pubKeyHex);
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s });
    expect(result.success).toBe(true);
  });

  it('rejects a proof with wrong s value', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = deriveChallenge(rHex, pubKeyHex);
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s: s + 1n });
    expect(result.success).toBe(false);
  });

  it('rejects a proof with wrong R point (tampered commitment)', () => {
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    // Compute valid proof for one R
    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);
    const e = deriveChallenge(rHex, pubKeyHex);
    const s = mod(r + e * privKey, EC_N);

    // Use a different R — the on-chain challenge will differ, breaking the proof
    const [rX2, rY2] = scalarMul(GX, GY, 99999n);
    const rHex2 = makePointHex(rX2, rY2);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex2, s });
    expect(result.success).toBe(false);
  });

  it('works with larger private key', () => {
    const privKey = 0xDEADBEEFCAFEn;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    const r = 0xABCDEF0123456789n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);

    const e = deriveChallenge(rHex, pubKeyHex);
    const s = mod(r + e * privKey, EC_N);

    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', { rPoint: rHex, s });
    expect(result.success).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // BUG-001 adversarial tests: s-bound malleability gate
  // ---------------------------------------------------------------------------

  it('rejects_s_at_n: s = secp256k1 group order is rejected (upper bound exclusive)', () => {
    // `within(s, 1, n)` is half-open [1, n); s = n must fail. This is the
    // canonical malleability witness — without the s-bound assert, any
    // valid s could be replaced with s + n and the script would still
    // verify (because k*G == (k + n)*G).
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);
    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', {
      rPoint: makePointHex(GX, GY),
      s: EC_N,
    });
    expect(result.success).toBe(false);
  });

  it('rejects_s_zero: s = 0 is rejected (lower bound inclusive but 0 < 1)', () => {
    // `within(s, 1, n)` requires s >= 1. s = 0 must fail. (Real signatures
    // never produce s = 0 because that would require r = -e*k mod n which
    // leaks the secret key, but the gate enforces it explicitly.)
    const privKey = 42n;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);
    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const result = c.call('verify', {
      rPoint: makePointHex(GX, GY),
      s: 0n,
    });
    expect(result.success).toBe(false);
  });

  it('nonce_reuse_recovers_key: reusing r across two proofs leaks the private key off-chain', () => {
    // Schnorr is fragile against nonce reuse — when two proofs (e1, s1) and
    // (e2, s2) reuse the same r:
    //   s1 = r + e1*k       s2 = r + e2*k
    //   s1 - s2 = (e1 - e2)*k     →     k = (e1 - e2)^{-1} * (s1 - s2)
    // Both proofs verify on-chain (they're individually valid). The bug is
    // an off-chain prover-side responsibility: this test demonstrates that
    // a key-recovery attack is feasible against any prover that reuses r.
    const privKey = 0xC0FFEEn;
    const [pubX, pubY] = scalarMul(GX, GY, privKey);
    const pubKeyHex = makePointHex(pubX, pubY);

    // Same nonce r for both proofs. Different messages → different
    // challenges. We need two distinct (R, P) → e pairs that share r;
    // since Fiat-Shamir derives e from (R, P), we vary P by re-running
    // the prover for two completely independent pubkeys... or, more
    // cleanly, we vary R itself but keep the inner scalar r constant.
    // The latter is what the prover would actually do if it
    // accidentally re-sampled r from a broken RNG. To keep the demo
    // self-contained we manufacture two distinct challenges off-chain
    // and check the algebra.
    const r = 12345n;
    const [rX, rY] = scalarMul(GX, GY, r);
    const rHex = makePointHex(rX, rY);
    const e1 = deriveChallenge(rHex, pubKeyHex);
    const s1 = mod(r + e1 * privKey, EC_N);
    // Fabricate a second challenge by perturbing the hash input (in
    // practice the prover would sign a second proof for a different P,
    // but for the algebraic demonstration any distinct e2 works).
    const e2 = mod(e1 + 1n, EC_N);
    const s2 = mod(r + e2 * privKey, EC_N);

    // Both proofs verify when run independently (this is the gotcha —
    // the on-chain verifier cannot detect r reuse). The key leak is
    // entirely off-chain:
    const recovered = mod((s1 - s2) * modInv(e1 - e2, EC_N), EC_N);
    expect(recovered).toBe(privKey);

    // Both proofs would individually pass the contract — we only verify
    // the first one (full e2-based proof requires the matching `rPoint`
    // and pubKey, which we don't materialise here; the algebraic recovery
    // above is the canonical demonstration).
    const c = TestContract.fromSource(source, { pubKey: pubKeyHex });
    const v1 = c.call('verify', { rPoint: rHex, s: s1 });
    expect(v1.success).toBe(true);
  });
});
