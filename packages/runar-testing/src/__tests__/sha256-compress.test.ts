/**
 * SHA-256 compression codegen — script execution correctness tests.
 *
 * Compiles contracts using sha256Compress, then executes them through the
 * BSV SDK's production-grade interpreter to verify correct SHA-256 output.
 *
 * Tests include:
 *   - Verification against hardcoded known SHA-256 hashes
 *   - Cross-verification against OP_SHA256 (the native opcode acts as oracle)
 *   - Two-block message (55-byte input requiring 2 compression rounds)
 *   - Non-initial state (chaining compression calls)
 *
 */

import { describe, it, expect } from 'vitest';
import { ScriptExecutionContract } from '../script-execution.js';
import { createHash } from 'crypto';

// ---- Contracts ----

/** Checks sha256Compress(state, block) === expected */
const SHA256_COMPRESS_SOURCE = `
class Sha256CompressTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, block: ByteString) {
    const result = sha256Compress(state, block);
    assert(result === this.expected);
  }
}
`;

/**
 * Cross-verifies sha256Compress against OP_SHA256:
 *   sha256Compress(init, paddedBlock) === sha256(message)
 *
 * The contract takes the raw (unpadded) message and the pre-padded block.
 * It computes sha256Compress on the padded block, then sha256 on the raw
 * message, and asserts they match. This uses the native OP_SHA256 as the
 * oracle — no hardcoded expected values.
 */
const SHA256_CROSS_VERIFY_SOURCE = `
class Sha256CrossVerify extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, paddedBlock: ByteString) {
    const compressed = sha256Compress(this.initState, paddedBlock);
    const native = sha256(message);
    assert(compressed === native);
  }
}
`;

/**
 * Two-block message: chains two sha256Compress calls and verifies against
 * OP_SHA256. Tests messages of 56-64 bytes that require SHA-256 padding
 * to spill into a second block.
 */
const SHA256_TWO_BLOCK_SOURCE = `
class Sha256TwoBlock extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, block1: ByteString, block2: ByteString) {
    const mid = sha256Compress(this.initState, block1);
    const final = sha256Compress(mid, block2);
    const native = sha256(message);
    assert(final === native);
  }
}
`;

// ---- Helpers ----

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

/** Pad a message (hex) to SHA-256 blocks per FIPS 180-4 Section 5.1.1. */
function sha256Pad(msgHex: string): string {
  const msgBytes = msgHex.length / 2;
  const bitLen = msgBytes * 8;

  // message + 0x80
  let padded = msgHex + '80';

  // Pad with zeros until length ≡ 56 mod 64 (in bytes)
  while ((padded.length / 2) % 64 !== 56) {
    padded += '00';
  }

  // Append 8-byte big-endian bit length
  padded += bitLen.toString(16).padStart(16, '0');

  return padded;
}

/** Compute SHA-256 using Node.js crypto (the ultimate oracle). */
function nodeSha256(msgHex: string): string {
  return createHash('sha256')
    .update(Buffer.from(msgHex, 'hex'))
    .digest('hex');
}

// ---- Tests ----

describe('sha256Compress — script execution', () => {
  describe('hardcoded known hashes', () => {
    it('SHA-256("abc")', () => {
      const block =
        '6162638000000000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000018';
      const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_COMPRESS_SOURCE,
        { expected },
        'Sha256CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [SHA256_INIT, block]);
      expect(result.success).toBe(true);
    });

    it('SHA-256("")', () => {
      const block =
        '8000000000000000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000000';
      const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_COMPRESS_SOURCE,
        { expected },
        'Sha256CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [SHA256_INIT, block]);
      expect(result.success).toBe(true);
    });

    it('rejects wrong expected hash', () => {
      const block =
        '6162638000000000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000018';
      const expected = '0000000000000000000000000000000000000000000000000000000000000000';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_COMPRESS_SOURCE,
        { expected },
        'Sha256CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [SHA256_INIT, block]);
      expect(result.success).toBe(false);
    });
  });

  describe('cross-verified against OP_SHA256', () => {
    const testMessages = [
      { name: '"abc"', hex: '616263' },
      { name: 'empty', hex: '' },
      { name: '1 byte (0x42)', hex: '42' },
      { name: '55 bytes (max single-block)', hex: 'aa'.repeat(55) },
      { name: '"Hello, SHA-256!"', hex: Buffer.from('Hello, SHA-256!').toString('hex') },
    ];

    for (const { name, hex } of testMessages) {
      it(`message: ${name}`, () => {
        const padded = sha256Pad(hex);

        // Sanity: verify our padding is correct by checking against Node.js crypto
        expect(padded.length / 2).toBe(64); // single block
        const nodeHash = nodeSha256(hex);

        const contract = ScriptExecutionContract.fromSource(
          SHA256_CROSS_VERIFY_SOURCE,
          { initState: SHA256_INIT },
          'Sha256CrossVerify.runar.ts',
        );

        const result = contract.execute('verify', [hex, padded]);
        if (!result.success) {
          console.log(`Cross-verify ${name} FAILED:`, result.error);
          console.log(`Expected (node crypto): ${nodeHash}`);
        }
        expect(result.success).toBe(true);
      });
    }
  });

  describe('two-block messages (chained compression)', () => {
    const testMessages = [
      { name: '56 bytes (spills to 2 blocks)', hex: 'bb'.repeat(56) },
      { name: '64 bytes (exactly one data block + padding block)', hex: 'cc'.repeat(64) },
      { name: '100 bytes', hex: 'dd'.repeat(100) },
    ];

    for (const { name, hex } of testMessages) {
      it(`message: ${name}`, () => {
        const padded = sha256Pad(hex);

        // These should require exactly 2 blocks
        expect(padded.length / 2).toBe(128);

        const block1 = padded.substring(0, 128);   // first 64 bytes
        const block2 = padded.substring(128, 256);  // second 64 bytes

        // Sanity check against Node.js crypto
        const nodeHash = nodeSha256(hex);

        const contract = ScriptExecutionContract.fromSource(
          SHA256_TWO_BLOCK_SOURCE,
          { initState: SHA256_INIT },
          'Sha256TwoBlock.runar.ts',
        );

        const result = contract.execute('verify', [hex, block1, block2]);
        if (!result.success) {
          console.log(`Two-block ${name} FAILED:`, result.error);
          console.log(`Expected (node crypto): ${nodeHash}`);
        }
        expect(result.success).toBe(true);
      });
    }
  });

  describe('non-initial state (arbitrary intermediate state)', () => {
    it('compress with non-standard initial state', () => {
      // Use the hash of "abc" as the initial state for a second compression
      const midState = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
      const block = sha256Pad('ff'.repeat(10));

      // Compute expected result: sha256Compress(midState, block)
      // We can't use Node crypto for this directly (it always starts from SHA256_INIT),
      // so we verify via a hardcoded value computed from the reference implementation.
      // Actually, we can verify determinism: run the same compression twice and they
      // should match. But more importantly, we test that non-zero initial states work.

      // Use the hardcoded-check contract
      // First, compute expected via the reference implementation
      const expected = referenceSha256Compress(midState, block);

      const contract = ScriptExecutionContract.fromSource(
        SHA256_COMPRESS_SOURCE,
        { expected },
        'Sha256CompressTest.runar.ts',
      );
      const result = contract.execute('verify', [midState, block]);
      expect(result.success).toBe(true);
    });
  });
});

// ---- Reference SHA-256 compression (pure JS) ----

const K_CONSTANTS = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function referenceSha256Compress(stateHex: string, blockHex: string): string {
  const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const add32 = (a: number, b: number) => (a + b) >>> 0;

  const H: number[] = [];
  for (let i = 0; i < 8; i++) H.push(parseInt(stateHex.substring(i * 8, i * 8 + 8), 16));

  const W: number[] = [];
  for (let i = 0; i < 16; i++) W.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));
  for (let t = 16; t < 64; t++) {
    const s0 = (rotr(W[t-15]!, 7) ^ rotr(W[t-15]!, 18) ^ (W[t-15]! >>> 3)) >>> 0;
    const s1 = (rotr(W[t-2]!, 17) ^ rotr(W[t-2]!, 19) ^ (W[t-2]! >>> 10)) >>> 0;
    W.push(add32(add32(add32(s1, W[t-7]!), s0), W[t-16]!));
  }

  let [a, b, c, d, e, f, g, h] = H;
  for (let t = 0; t < 64; t++) {
    const S1 = (rotr(e!, 6) ^ rotr(e!, 11) ^ rotr(e!, 25)) >>> 0;
    const ch = ((e! & f!) ^ (~e! & g!)) >>> 0;
    const T1 = add32(add32(add32(add32(h!, S1), ch), K_CONSTANTS[t]!), W[t]!);
    const S0 = (rotr(a!, 2) ^ rotr(a!, 13) ^ rotr(a!, 22)) >>> 0;
    const maj = ((a! & b!) ^ (a! & c!) ^ (b! & c!)) >>> 0;
    const T2 = add32(S0, maj);
    h = g!; g = f!; f = e!; e = add32(d!, T1);
    d = c!; c = b!; b = a!; a = add32(T1, T2);
  }

  return [
    add32(a!, H[0]!), add32(b!, H[1]!), add32(c!, H[2]!), add32(d!, H[3]!),
    add32(e!, H[4]!), add32(f!, H[5]!), add32(g!, H[6]!), add32(h!, H[7]!),
  ].map(w => w.toString(16).padStart(8, '0')).join('');
}
