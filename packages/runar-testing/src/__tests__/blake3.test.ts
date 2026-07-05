/**
 * BLAKE3 compression codegen — script execution correctness tests.
 *
 * Compiles contracts using blake3Compress and blake3Hash, then executes
 * them through the BSV SDK interpreter to verify correct BLAKE3 output.
 *
 * Reference: BLAKE3 spec (https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf)
 */

import { describe, it, expect } from 'vitest';
import { ScriptExecutionContract } from '../script-execution.js';

// ---- Contracts ----

const BLAKE3_COMPRESS_SOURCE = `
class Blake3CompressTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(chainingValue: ByteString, block: ByteString) {
    const result = blake3Compress(chainingValue, block);
    assert(result === this.expected);
  }
}
`;

const BLAKE3_HASH_SOURCE = `
class Blake3HashTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(message: ByteString) {
    const result = blake3Hash(message);
    assert(result === this.expected);
  }
}
`;

// ---- Reference BLAKE3 implementation (single block, ≤64 bytes) ----

const BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

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

function g(state: number[], a: number, b: number, c: number, d: number, mx: number, my: number): void {
  state[a] = add32(add32(state[a]!, state[b]!), mx);
  state[d] = rotr32(state[d]! ^ state[a]!, 16);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 12);
  state[a] = add32(add32(state[a]!, state[b]!), my);
  state[d] = rotr32(state[d]! ^ state[a]!, 8);
  state[c] = add32(state[c]!, state[d]!);
  state[b] = rotr32(state[b]! ^ state[c]!, 7);
}

function round(state: number[], m: number[]): void {
  // Columns
  g(state, 0, 4, 8, 12, m[0]!, m[1]!);
  g(state, 1, 5, 9, 13, m[2]!, m[3]!);
  g(state, 2, 6, 10, 14, m[4]!, m[5]!);
  g(state, 3, 7, 11, 15, m[6]!, m[7]!);
  // Diagonals
  g(state, 0, 5, 10, 15, m[8]!, m[9]!);
  g(state, 1, 6, 11, 12, m[10]!, m[11]!);
  g(state, 2, 7, 8, 13, m[12]!, m[13]!);
  g(state, 3, 4, 9, 14, m[14]!, m[15]!);
}

function permute(m: number[]): number[] {
  return MSG_PERM.map(i => m[i]!);
}

/**
 * Reference BLAKE3 compression function (standard, little-endian).
 * The chaining value and block are little-endian byte strings (a 4-byte
 * byte-string is a little-endian word); the digest is output little-endian.
 * @param cvHex - 32-byte chaining value as hex
 * @param blockHex - 64-byte block as hex
 * @param blockLen - number of actual message bytes in the block
 * @param flags - BLAKE3 flags
 * @returns 32-byte hash as hex
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

  // Initialize state
  const state: number[] = [
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0,  // counter low
    0,  // counter high
    blockLen,
    flags,
  ];

  // 7 rounds
  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    round(state, msg);
    if (r < 6) msg = permute(msg);
  }

  // Output: little-endian bytes of h[i] = state[i] ^ state[i+8]
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

/** Standard BLAKE3 hash of a message ≤ 64 bytes (single block, real block_len). */
function referenceBlake3Hash(msgHex: string): string {
  const ivLe = Buffer.alloc(32);
  for (let i = 0; i < 8; i++) ivLe.writeUInt32LE(BLAKE3_IV[i]! >>> 0, i * 4);
  const padded = msgHex.padEnd(128, '0');
  return referenceBlake3Compress(ivLe.toString('hex'), padded, msgHex.length / 2, CHUNK_START | CHUNK_END | ROOT);
}

// ---- Tests ----

const BLAKE3_IV_HEX = BLAKE3_IV.map(w => w.toString(16).padStart(8, '0')).join('');

describe('blake3Compress — script execution', () => {
  describe('hardcoded known hashes', () => {
    it('BLAKE3 hash of empty input', () => {
      const block = '00'.repeat(64);
      // The codegen hardcodes blockLen=64 and flags=11 (CHUNK_START|CHUNK_END|ROOT)
      const expectedWith64 = referenceBlake3Compress(BLAKE3_IV_HEX, block, 64, CHUNK_START | CHUNK_END | ROOT);

      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_COMPRESS_SOURCE,
        { expected: expectedWith64 },
        'Blake3CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [BLAKE3_IV_HEX, block]);
      expect(result.success).toBe(true);
    });

    it('BLAKE3 compress with "abc" (padded to 64 bytes)', () => {
      const msg = '616263' + '00'.repeat(61);
      const expected = referenceBlake3Compress(BLAKE3_IV_HEX, msg, 64, CHUNK_START | CHUNK_END | ROOT);

      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_COMPRESS_SOURCE,
        { expected },
        'Blake3CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [BLAKE3_IV_HEX, msg]);
      if (!result.success) {
        console.log('BLAKE3 compress "abc" FAILED:', result.error);
        console.log('Expected:', expected);
      }
      expect(result.success).toBe(true);
    });

    it('rejects wrong expected hash', () => {
      const block = '616263' + '00'.repeat(61);
      const wrong = '00'.repeat(32);

      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_COMPRESS_SOURCE,
        { expected: wrong },
        'Blake3CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [BLAKE3_IV_HEX, block]);
      expect(result.success).toBe(false);
    });
  });

  describe('multiple test vectors', () => {
    const testCases = [
      { name: '1 byte (0x42)', hex: '42' },
      { name: '3 bytes (abc)', hex: '616263' },
      { name: '55 bytes', hex: 'aa'.repeat(55) },
      { name: '64 bytes (full block)', hex: 'ff'.repeat(64) },
      { name: 'sequential bytes', hex: Array.from({ length: 64 }, (_, i) => i.toString(16).padStart(2, '0')).join('') },
    ];

    for (const { name, hex } of testCases) {
      it(`blake3Compress: ${name}`, () => {
        // Pad to 64 bytes
        const padded = hex.padEnd(128, '0');
        const expected = referenceBlake3Compress(BLAKE3_IV_HEX, padded, 64, CHUNK_START | CHUNK_END | ROOT);

        const contract = ScriptExecutionContract.fromSource(
          BLAKE3_COMPRESS_SOURCE,
          { expected },
          'Blake3CompressTest.runar.ts',
        );
        const result = contract.execute('verify', [BLAKE3_IV_HEX, padded]);
        if (!result.success) {
          console.log(`BLAKE3 ${name} FAILED:`, result.error);
          console.log('Expected:', expected);
        }
        expect(result.success).toBe(true);
      });
    }
  });
});

describe('blake3Hash — script execution', () => {
  const testMessages = [
    { name: 'empty', hex: '' },
    { name: '"abc"', hex: '616263' },
    { name: '1 byte (0x00)', hex: '00' },
    { name: '32 bytes', hex: 'ab'.repeat(32) },
    { name: '64 bytes (full block)', hex: 'cd'.repeat(64) },
  ];

  for (const { name, hex } of testMessages) {
    it(`blake3Hash: ${name}`, () => {
      // blake3Hash uses the real message length as block_len (standard BLAKE3).
      const expected = referenceBlake3Hash(hex);

      const contract = ScriptExecutionContract.fromSource(
        BLAKE3_HASH_SOURCE,
        { expected },
        'Blake3HashTest.runar.ts',
      );
      const result = contract.execute('verify', [hex]);
      if (!result.success) {
        console.log(`blake3Hash ${name} FAILED:`, result.error);
        console.log('Expected:', expected);
      }
      expect(result.success).toBe(true);
    });
  }
});
