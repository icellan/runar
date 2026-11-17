/**
 * GK-BUG-013 (off-chain half): the interpreter's sha256Finalize must refuse a
 * msgBitLen outside [0, 2^64), the domain the compiled script now enforces.
 *
 * On-chain, `<9> OP_NUM2BIN <8> OP_SPLIT` leaves the script-number sign (or the
 * 2^64 byte) in a 9th byte that the fix requires to be 0x00; every tier's
 * emitter is pinned by conformance/negatives/gk-bug-013-sha256-finalize-bitlen-domain.test.ts.
 * The interpreter wrote the length with `DataView.setBigUint64`, which wraps
 * modulo 2^64: -24 became 2^64 - 24 (a digest no engine computes) and
 * 2^64 + 24 became 24 (the same alias the old script accepted). Either way the
 * two engines disagreed with the script, which is what the differential oracle
 * exists to prevent.
 *
 * What this proves: TestContract refuses -24 and 2^64 + 24 with the shared
 * "msgBitLen must be in [0, 2^64)" diagnostic, still computes SHA-256('abc')
 * for 24 (node's SHA-256 is the oracle), and accepts the top of the domain
 * (2^64 - 8 and 2^63 + 24, against a FIPS 180-4 reference anchored to node).
 * What it does NOT prove: the other six tiers' off-chain implementations (each
 * has its own gk-bug-013 test).
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';
import { TestContract } from '../index.js';

const IV = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
const ABC_HEX = '616263';
const SHA_ABC = createHash('sha256').update('abc').digest('hex');

const SRC = `
import { SmartContract, assert, sha256Finalize } from 'runar-lang';

class FinalizeProbe extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    assert(sha256Finalize(state, remaining, msgBitLen) === this.expected);
  }
}
`;

// FIPS 180-4 single-block compression, used only for lengths node cannot set.
const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
function refFinalize1(tailHex: string, lengthField: bigint): string {
  const state = Buffer.from(IV, 'hex');
  const tail = Buffer.from(tailHex, 'hex');
  const block = Buffer.alloc(64);
  tail.copy(block);
  block[tail.length] = 0x80;
  block.writeBigUInt64BE(lengthField, 56);
  const H = Array.from({ length: 8 }, (_, i) => state.readUInt32BE(i * 4));
  const W = Array.from({ length: 16 }, (_, i) => block.readUInt32BE(i * 4));
  for (let t = 16; t < 64; t++) {
    const s0 = rotr(W[t - 15]!, 7) ^ rotr(W[t - 15]!, 18) ^ (W[t - 15]! >>> 3);
    const s1 = rotr(W[t - 2]!, 17) ^ rotr(W[t - 2]!, 19) ^ (W[t - 2]! >>> 10);
    W.push((W[t - 16]! + s0 + W[t - 7]! + s1) >>> 0);
  }
  let [a, b, c, d, e, f, g, h] = H as [number, number, number, number, number, number, number, number];
  for (let t = 0; t < 64; t++) {
    const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t]! + W[t]!) >>> 0;
    const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
    h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
  }
  const out = Buffer.alloc(32);
  [a, b, c, d, e, f, g, h].forEach((x, i) => out.writeUInt32BE((H[i]! + x) >>> 0, i * 4));
  return out.toString('hex');
}

function run(expected: string, msgBitLen: bigint): { success: boolean; error?: string } {
  const c = TestContract.fromSource(SRC, { expected }, 'FinalizeProbe.runar.ts');
  const r = c.call('verify', { state: IV, remaining: ABC_HEX, msgBitLen });
  return { success: r.success, error: r.error };
}

const DOMAIN = /sha256Finalize: msgBitLen must be in \[0, 2\^64\), got /;

describe('GK-BUG-013: the interpreter refuses msgBitLen outside [0, 2^64)', () => {
  it('the reference is anchored: refFinalize1("abc", 24) is node SHA-256("abc")', () => {
    expect(refFinalize1(ABC_HEX, 24n)).toBe(SHA_ABC);
  });

  it('24 still computes SHA-256("abc")', () => {
    const r = run(SHA_ABC, 24n);
    expect(r.success, r.error).toBe(true);
  });

  it('-24 is refused with the domain diagnostic (it used to wrap to 2^64 - 24)', () => {
    const r = run(SHA_ABC, -24n);
    expect(r.success).toBe(false);
    expect(r.error ?? '').toMatch(DOMAIN);
    expect(r.error ?? '').toMatch(/got -24\b/);
  });

  it('2^64 + 24 is refused with the domain diagnostic (it used to alias 24 and ACCEPT)', () => {
    const r = run(SHA_ABC, (1n << 64n) + 24n);
    expect(r.success).toBe(false);
    expect(r.error ?? '').toMatch(DOMAIN);
    expect(r.error ?? '').toMatch(/got 18446744073709551640\b/);
  });

  it('the top of the domain is accepted: 2^63 + 24 and 2^64 - 8', () => {
    for (const len of [(1n << 63n) + 24n, (1n << 64n) - 8n]) {
      const r = run(refFinalize1(ABC_HEX, len), len);
      expect(r.success, `${len}: ${r.error}`).toBe(true);
    }
  });
});
