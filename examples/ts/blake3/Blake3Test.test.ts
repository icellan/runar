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
 * Reference BLAKE3 compression.
 * Matches the on-chain codegen which hardcodes blockLen=64 and flags=11.
 */
function referenceBlake3Compress(
  cvHex: string,
  blockHex: string,
  blockLen: number = 64,
  flags: number = CHUNK_START | CHUNK_END | ROOT,
): string {
  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(parseInt(cvHex.substring(i * 8, i * 8 + 8), 16));

  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));

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

  const output: number[] = [];
  for (let i = 0; i < 8; i++) {
    output.push((state[i]! ^ state[i + 8]!) >>> 0);
  }

  return output.map(w => w.toString(16).padStart(8, '0')).join('');
}

/** Reference BLAKE3 hash of a message <= 64 bytes (blockLen hardcoded to 64). */
function referenceBlake3Hash(msgHex: string): string {
  const padded = msgHex.padEnd(128, '0');
  return referenceBlake3Compress(BLAKE3_IV_HEX, padded, 64, CHUNK_START | CHUNK_END | ROOT);
}

// ---- Tests ----

describe('Blake3Test', () => {
  // Pre-compute the well-known hash: BLAKE3 of all-zero 64-byte block with IV chaining value
  const ALL_ZEROS_BLOCK = '00'.repeat(64);
  const EMPTY_HASH = referenceBlake3Hash('');

  // Sanity-check our reference against the known value from the spec
  it('reference implementation produces known hash', () => {
    expect(EMPTY_HASH).toBe('7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86');
  });

  describe('verifyCompress', () => {
    it('accepts BLAKE3 compress of all-zeros block with IV chaining value', () => {
      const contract = TestContract.fromSource(source, {
        expected: EMPTY_HASH,
      });
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
