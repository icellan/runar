/**
 * F-114 — `blake3Compress` / `sha256Compress` / `sha256Finalize` must refuse
 * mis-sized operands on-chain.
 *
 * The compiled compress bodies split the block into 4-byte words and add them
 * as script numbers that are truncated back to 32 bits (`num2le`). Without an
 * operand size check:
 *   - a 65-byte block `B || 0x01` leaves a 5-byte last word whose fifth byte
 *     is the 2^32 bit of an addend and is thrown away, so it yields the same
 *     digest as `B`;
 *   - a 60..63-byte block leaves a short last word that is zero-extended, so it
 *     yields the same digest as its zero-padded 64-byte form;
 *   - a mis-sized chaining value / state has the same shape.
 * A contract that asserts `blake3Compress(cv, block) === committed` and then
 * also uses `block` (extracts or forwards a field) can be fed a second,
 * different `block` with the committed digest.
 *
 * Oracle: @bsv/sdk's production `Spend` (via `runStatelessSigned`, consensus
 * flags). The honest digests come from references written here, which are
 * themselves pinned to the official BLAKE3 64-byte KAT and to node's SHA-256,
 * never to the codegen under test.
 *
 * What this proves: on the TS-tier compiled script, every honest 32/64-byte
 * call is accepted, and each forced near-miss (65-byte block with the honest
 * digest, 60..63-byte zero-extension block with the honest digest, 31/33-byte
 * chaining value / state) is refused, for blake3Compress, sha256Compress and
 * sha256Finalize's state. The ANF interpreter agrees on every row.
 * What it does NOT prove: anything about the six peer tiers (pinned by the
 * conformance goldens, their real-crypto witnesses and per-tier unit tests),
 * nor any cryptographic property of BLAKE3 / SHA-256 themselves.
 */
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

// ---------------------------------------------------------------------------
// Independent references
// ---------------------------------------------------------------------------

const B3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const B3_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
const add = (a: number, b: number) => (a + b) >>> 0;

function leWords(b: Uint8Array, n: number): number[] {
  if (b.length !== n * 4) throw new Error(`reference: need ${n * 4} bytes, got ${b.length}`);
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    out.push((b[i * 4]! | (b[i * 4 + 1]! << 8) | (b[i * 4 + 2]! << 16) | (b[i * 4 + 3]! << 24)) >>> 0);
  }
  return out;
}

/** BLAKE3 compress, block_len = 64, flags = CHUNK_START|CHUNK_END|ROOT. */
function refBlake3Compress(cv: Uint8Array, block: Uint8Array): Uint8Array {
  const h = leWords(cv, 8);
  let m = leWords(block, 16);
  const v = [...h, B3_IV[0]!, B3_IV[1]!, B3_IV[2]!, B3_IV[3]!, 0, 0, 64, 1 | 2 | 8];
  const g = (a: number, b: number, c: number, d: number, x: number, y: number) => {
    v[a] = add(add(v[a]!, v[b]!), x); v[d] = rotr(v[d]! ^ v[a]!, 16);
    v[c] = add(v[c]!, v[d]!); v[b] = rotr(v[b]! ^ v[c]!, 12);
    v[a] = add(add(v[a]!, v[b]!), y); v[d] = rotr(v[d]! ^ v[a]!, 8);
    v[c] = add(v[c]!, v[d]!); v[b] = rotr(v[b]! ^ v[c]!, 7);
  };
  for (let r = 0; r < 7; r++) {
    g(0, 4, 8, 12, m[0]!, m[1]!); g(1, 5, 9, 13, m[2]!, m[3]!);
    g(2, 6, 10, 14, m[4]!, m[5]!); g(3, 7, 11, 15, m[6]!, m[7]!);
    g(0, 5, 10, 15, m[8]!, m[9]!); g(1, 6, 11, 12, m[10]!, m[11]!);
    g(2, 7, 8, 13, m[12]!, m[13]!); g(3, 4, 9, 14, m[14]!, m[15]!);
    m = B3_PERM.map((i) => m[i]!);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    const w = (v[i]! ^ v[i + 8]!) >>> 0;
    out[i * 4] = w & 0xff; out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff; out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out;
}

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

function beWords(b: Uint8Array, n: number): number[] {
  if (b.length !== n * 4) throw new Error(`reference: need ${n * 4} bytes, got ${b.length}`);
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    out.push(((b[i * 4]! << 24) | (b[i * 4 + 1]! << 16) | (b[i * 4 + 2]! << 8) | b[i * 4 + 3]!) >>> 0);
  }
  return out;
}

/** FIPS 180-4 §6.2.2 single-block SHA-256 compression. */
function refSha256Compress(state: Uint8Array, block: Uint8Array): Uint8Array {
  const H = beWords(state, 8);
  const W = beWords(block, 16);
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
  const out = new Uint8Array(32);
  [a, b, c, d, e, f, g, h].forEach((x, i) => {
    const w = (H[i]! + x) >>> 0;
    out[i * 4] = w >>> 24; out[i * 4 + 1] = (w >>> 16) & 0xff;
    out[i * 4 + 2] = (w >>> 8) & 0xff; out[i * 4 + 3] = w & 0xff;
  });
  return out;
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const unhex = (s: string) => new Uint8Array(Buffer.from(s, 'hex'));
const cat = (a: Uint8Array, b: Uint8Array) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a); o.set(b, a.length);
  return o;
};

const B3_IV_BYTES = new Uint8Array(32);
B3_IV.forEach((w, i) => {
  B3_IV_BYTES[i * 4] = w & 0xff; B3_IV_BYTES[i * 4 + 1] = (w >>> 8) & 0xff;
  B3_IV_BYTES[i * 4 + 2] = (w >>> 16) & 0xff; B3_IV_BYTES[i * 4 + 3] = (w >>> 24) & 0xff;
});
const SHA_IV = unhex('6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19');

/** Official BLAKE3 KAT, input_len 64 (byte i = i % 251) — conformance/runtime-vectors/blake3-official-kat.json. */
const KAT64_INPUT = Uint8Array.from({ length: 64 }, (_, i) => i % 251);
const KAT64_HASH = '4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98';

/** FIPS 180-4 padded single block of 'abc'. */
const ABC = new TextEncoder().encode('abc');
const ABC_BLOCK = (() => {
  const b = new Uint8Array(64);
  b.set(ABC); b[3] = 0x80; b[63] = 24;
  return b;
})();

/** A 64-byte block whose last four bytes are zero: its 60..63-byte prefixes are the zero-extension near-miss. */
const ZERO_TAIL_BLOCK = (() => {
  const b = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff);
  b.fill(0, 60);
  return b;
})();

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

const contract = (name: string, call: string, params: string) => `
import { SmartContract, assert, ByteString, ${name} } from 'runar-lang';

class Check extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(${params}) {
    assert(${call} === this.expected);
  }
}
`;

const B3_SRC = contract('blake3Compress', 'blake3Compress(cv, block)', 'cv: ByteString, block: ByteString');
const SHA_SRC = contract('sha256Compress', 'sha256Compress(state, block)', 'state: ByteString, block: ByteString');
const FIN_SRC = contract(
  'sha256Finalize',
  'sha256Finalize(state, remaining, msgBitLen)',
  'state: ByteString, remaining: ByteString, msgBitLen: bigint',
);

function run(source: string, expected: Uint8Array, args: (Uint8Array | bigint)[]) {
  const r = runStatelessSigned({
    source,
    fileName: 'Check.runar.ts',
    method: 'verify',
    args,
    constructorArgs: { expected: hex(expected) },
  });
  expect(r.reachedEngine).toBe(true);
  return r;
}

function expectAccept(r: ReturnType<typeof run>) {
  expect(r.vmAccepted, `Spend refused an honest call: ${r.vmError}`).toBe(true);
  expect(r.interpreterAccepted, `interpreter: ${r.interpreterError}`).toBe(true);
}

function expectReject(r: ReturnType<typeof run>) {
  expect(r.vmAccepted, 'Spend accepted a mis-sized operand with the honest digest').toBe(false);
  expect(r.interpreterAccepted).toBe(false);
}

// ---------------------------------------------------------------------------

describe('F-114: references are pinned to independent anchors', () => {
  it('BLAKE3 compress(IV, 64-byte KAT input) equals the official KAT', () => {
    expect(hex(refBlake3Compress(B3_IV_BYTES, KAT64_INPUT))).toBe(KAT64_HASH);
  });
  it("SHA-256 compress(IV, padded 'abc') equals node sha256('abc')", () => {
    expect(hex(refSha256Compress(SHA_IV, ABC_BLOCK))).toBe(createHash('sha256').update(ABC).digest('hex'));
  });
});

describe('F-114: blake3Compress refuses mis-sized operands on Spend', () => {
  const digest = unhex(KAT64_HASH);

  it('honest 32-byte cv + 64-byte block: ACCEPT', () => {
    expectAccept(run(B3_SRC, digest, [B3_IV_BYTES, KAT64_INPUT]));
  });

  it('65-byte block B || 0x01 with the digest of B: REJECT', () => {
    expectReject(run(B3_SRC, digest, [B3_IV_BYTES, cat(KAT64_INPUT, new Uint8Array([0x01]))]));
  });

  it('zero-tail block: honest 64 bytes ACCEPT, every 60..63-byte prefix REJECT', () => {
    const d = refBlake3Compress(B3_IV_BYTES, ZERO_TAIL_BLOCK);
    expectAccept(run(B3_SRC, d, [B3_IV_BYTES, ZERO_TAIL_BLOCK]));
    for (const len of [60, 61, 62, 63]) {
      expectReject(run(B3_SRC, d, [B3_IV_BYTES, ZERO_TAIL_BLOCK.subarray(0, len)]));
    }
  });

  it('31- and 33-byte chaining value with the honest digest: REJECT', () => {
    expectReject(run(B3_SRC, digest, [B3_IV_BYTES.subarray(0, 31), KAT64_INPUT]));
    expectReject(run(B3_SRC, digest, [cat(B3_IV_BYTES, new Uint8Array([0x01])), KAT64_INPUT]));
  });
});

describe('F-114: sha256Compress refuses mis-sized operands on Spend', () => {
  const digest = createHash('sha256').update(ABC).digest();

  it("honest 32-byte state + padded 'abc' block: ACCEPT", () => {
    expectAccept(run(SHA_SRC, digest, [SHA_IV, ABC_BLOCK]));
  });

  it('65-byte block B || 0x01 with the digest of B: REJECT', () => {
    expectReject(run(SHA_SRC, digest, [SHA_IV, cat(ABC_BLOCK, new Uint8Array([0x01]))]));
  });

  it('zero-tail block: honest 64 bytes ACCEPT, every 60..63-byte prefix REJECT', () => {
    const d = refSha256Compress(SHA_IV, ZERO_TAIL_BLOCK);
    expectAccept(run(SHA_SRC, d, [SHA_IV, ZERO_TAIL_BLOCK]));
    for (const len of [60, 61, 62, 63]) {
      expectReject(run(SHA_SRC, d, [SHA_IV, ZERO_TAIL_BLOCK.subarray(0, len)]));
    }
  });

  it('31- and 33-byte state with the honest digest: REJECT', () => {
    expectReject(run(SHA_SRC, digest, [SHA_IV.subarray(0, 31), ABC_BLOCK]));
    expectReject(run(SHA_SRC, digest, [cat(SHA_IV, new Uint8Array([0x01])), ABC_BLOCK]));
  });
});

describe('F-114: sha256Finalize refuses a mis-sized state on Spend', () => {
  const digest = createHash('sha256').update(ABC).digest();

  it("honest 32-byte state, remaining 'abc', 24 bits: ACCEPT", () => {
    expectAccept(run(FIN_SRC, digest, [SHA_IV, ABC, 24n]));
  });

  it('31- and 33-byte state with the honest digest: REJECT', () => {
    expectReject(run(FIN_SRC, digest, [SHA_IV.subarray(0, 31), ABC, 24n]));
    expectReject(run(FIN_SRC, digest, [cat(SHA_IV, new Uint8Array([0x01])), ABC, 24n]));
  });

  it('remaining of 120 bytes (outside the 0..119 domain): REJECT', () => {
    const rem = new Uint8Array(120).fill(0x61);
    expectReject(run(FIN_SRC, digest, [SHA_IV, rem, 960n]));
  });
});
