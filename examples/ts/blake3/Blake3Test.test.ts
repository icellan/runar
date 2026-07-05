import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'Blake3Test.runar.ts'), 'utf8');

// ---- Compact reference BLAKE3 implementation (single block, <= 64 bytes) ----

const BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const BLAKE3_IV_HEX = BLAKE3_IV.map(w => w.toString(16).padStart(8, '0')).join('');

const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START = 1;
const CHUNK_END = 2;
const ROOT = 8;

function rotr32(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function add32(a: number, b: number): number {
  return (a + b) >>> 0;
}

function g(
  state: number[], a: number, b: number, c: number, d: number,
  mx: number, my: number,
): void {
  state[a] = add32(add32(state[a]!, state[b]!), mx);
  state[d] = rotr32(state[d]! ^ state[a]!, 16);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 12);
  state[a] = add32(add32(state[a]!, state[b]!), my);
  state[d] = rotr32(state[d]! ^ state[a]!, 8);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 7);
}

function blake3Round(state: number[], m: number[]): void {
  g(state, 0, 4, 8, 12, m[0]!, m[1]!);
  g(state, 1, 5, 9, 13, m[2]!, m[3]!);
  g(state, 2, 6, 10, 14, m[4]!, m[5]!);
  g(state, 3, 7, 11, 15, m[6]!, m[7]!);
  g(state, 0, 5, 10, 15, m[8]!, m[9]!);
  g(state, 1, 6, 11, 12, m[10]!, m[11]!);
  g(state, 2, 7, 8, 13, m[12]!, m[13]!);
  g(state, 3, 4, 9, 14, m[14]!, m[15]!);
}

function permute(m: number[]): number[] {
  return MSG_PERM.map(i => m[i]!);
}

/**
 * Reference BLAKE3 single-block compression (standard, little-endian).
 * The chaining value and block are little-endian byte strings (a 4-byte
 * byte-string is a little-endian word), and the digest is output little-endian.
 */
function referenceBlake3Compress(
  cvHex: string,
  blockHex: string,
  blockLen: number = 64,
  flags: number = CHUNK_START | CHUNK_END | ROOT,
): string {
  const cvB = Buffer.from(cvHex, 'hex');
  const blockB = Buffer.from(blockHex, 'hex');
  const le = (b: Buffer, i: number) =>
    ((b[i * 4]! | (b[i * 4 + 1]! << 8) | (b[i * 4 + 2]! << 16) | (b[i * 4 + 3]! << 24)) >>> 0);

  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(le(cvB, i));
  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(le(blockB, i));

  const state: number[] = [
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0, 0, blockLen, flags,
  ];

  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    blake3Round(state, msg);
    if (r < 6) msg = permute(msg);
  }

  // Output little-endian bytes of h[i] = state[i] ^ state[i+8]
  const out = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) {
    const w = (state[i]! ^ state[i + 8]!) >>> 0;
    out[i * 4] = w & 0xff;
    out[i * 4 + 1] = (w >>> 8) & 0xff;
    out[i * 4 + 2] = (w >>> 16) & 0xff;
    out[i * 4 + 3] = (w >>> 24) & 0xff;
  }
  return out.toString('hex');
}

/** Reference standard BLAKE3 hash of a message <= 64 bytes (single block). */
function referenceBlake3Hash(msgHex: string): string {
  // IV as little-endian bytes (standard BLAKE3 chaining value).
  const ivLe = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) ivLe.writeUInt32LE(BLAKE3_IV[i]! >>> 0, i * 4);
  const padded = msgHex.padEnd(128, '0');
  return referenceBlake3Compress(ivLe.toString('hex'), padded, msgHex.length / 2, CHUNK_START | CHUNK_END | ROOT);
}

// ---- Tests ----

describe('Blake3Test', () => {
  // Pre-compute the well-known hash: BLAKE3 of all-zero 64-byte block with IV chaining value
  const ALL_ZEROS_BLOCK = '00'.repeat(64);
  const EMPTY_HASH = referenceBlake3Hash('');

  // Sanity-check our reference against the official BLAKE3 empty-string KAT
  it('reference implementation produces known hash', () => {
    expect(EMPTY_HASH).toBe('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262');
  });

  describe('verifyCompress', () => {
    it('accepts BLAKE3 compress of all-zeros block with IV chaining value', () => {
      // blake3Compress uses block_len=64 (a full 64-byte block), so this is NOT
      // the empty-string hash (which uses block_len=0) — compute it explicitly.
      const expected = referenceBlake3Compress(BLAKE3_IV_HEX, ALL_ZEROS_BLOCK);
      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyCompress', {
        chainingValue: BLAKE3_IV_HEX,
        block: ALL_ZEROS_BLOCK,
      });
      expect(result.success).toBe(true);
    });

    it('accepts BLAKE3 compress of "abc" padded to 64 bytes', () => {
      const abcBlock = '616263' + '00'.repeat(61);
      const expected = referenceBlake3Compress(BLAKE3_IV_HEX, abcBlock);

      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyCompress', {
        chainingValue: BLAKE3_IV_HEX,
        block: abcBlock,
      });
      expect(result.success).toBe(true);
    });

    it('accepts BLAKE3 compress with non-IV chaining value', () => {
      const customCV = 'deadbeef'.repeat(8);
      const block = 'ff'.repeat(64);
      const expected = referenceBlake3Compress(customCV, block);

      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyCompress', {
        chainingValue: customCV,
        block,
      });
      expect(result.success).toBe(true);
    });
  });

  describe('verifyHash', () => {
    it('accepts BLAKE3 hash of empty message', () => {
      const contract = TestContract.fromSource(source, {
        expected: EMPTY_HASH,
      });
      const result = contract.call('verifyHash', { message: '' });
      expect(result.success).toBe(true);
    });

    it('accepts BLAKE3 hash of "abc"', () => {
      const expected = referenceBlake3Hash('616263');
      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyHash', { message: '616263' });
      expect(result.success).toBe(true);
    });

    it('accepts BLAKE3 hash of 32-byte message', () => {
      const msg = 'ab'.repeat(32);
      const expected = referenceBlake3Hash(msg);
      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyHash', { message: msg });
      expect(result.success).toBe(true);
    });

    it('accepts BLAKE3 hash of full 64-byte message', () => {
      const msg = 'cd'.repeat(64);
      const expected = referenceBlake3Hash(msg);
      const contract = TestContract.fromSource(source, { expected });
      const result = contract.call('verifyHash', { message: msg });
      expect(result.success).toBe(true);
    });
  });

  describe('rejection', () => {
    it('rejects wrong expected hash for verifyCompress', () => {
      const wrongHash = '00'.repeat(32);
      const contract = TestContract.fromSource(source, {
        expected: wrongHash,
      });
      const result = contract.call('verifyCompress', {
        chainingValue: BLAKE3_IV_HEX,
        block: ALL_ZEROS_BLOCK,
      });
      expect(result.success).toBe(false);
    });

    it('rejects wrong expected hash for verifyHash', () => {
      const wrongHash = 'ff'.repeat(32);
      const contract = TestContract.fromSource(source, {
        expected: wrongHash,
      });
      const result = contract.call('verifyHash', { message: '616263' });
      expect(result.success).toBe(false);
    });
  });
});
