/**
 * SHA-256 finalize codegen — script execution correctness tests.
 *
 * Compiles contracts using sha256Finalize, then executes them through the
 * BSV SDK's production-grade interpreter to verify correct SHA-256 output.
 *
 * Tests include:
 *   - Verification against hardcoded known SHA-256 hashes
 *   - Cross-verification against OP_SHA256 (the native opcode acts as oracle)
 *   - Two-block finalize (56-119 byte messages requiring 2-block padding)
 *   - Chained sha256Compress + sha256Finalize
 *   - Non-initial state finalize
 */

import { describe, it, expect } from 'vitest';
import { ScriptExecutionContract } from '../script-execution.js';
import { createHash } from 'crypto';

// ---- Contracts ----

/** Checks sha256Finalize(state, remaining, msgBitLen) === expected */
const SHA256_FINALIZE_SOURCE = `
class Sha256FinalizeTest extends SmartContract {
  readonly expected: ByteString;

  constructor(expected: ByteString) {
    super(expected);
    this.expected = expected;
  }

  public verify(state: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const result = sha256Finalize(state, remaining, msgBitLen);
    assert(result === this.expected);
  }
}
`;

/**
 * Cross-verifies sha256Finalize against OP_SHA256:
 *   sha256Finalize(initState, message, bitLen) === sha256(message)
 *
 * The contract takes the raw message and its bit length. sha256Finalize
 * internally handles FIPS 180-4 padding (append 0x80, zero-pad, append
 * 8-byte bit length) and branches between 1-block (remaining <= 55 bytes)
 * and 2-block (56-119 bytes) paths.
 */
const SHA256_FINALIZE_CROSS_VERIFY_SOURCE = `
class Sha256FinalizeCrossVerify extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, msgBitLen: bigint) {
    const finalized = sha256Finalize(this.initState, message, msgBitLen);
    const native = sha256(message);
    assert(finalized === native);
  }
}
`;

/**
 * Chained: sha256Compress first block + sha256Finalize remainder.
 * Verifies multi-block messages that span both compress and finalize.
 */
const SHA256_FINALIZE_CHAINED_SOURCE = `
class Sha256FinalizeChained extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(fullMessage: ByteString, firstBlock: ByteString, remaining: ByteString, totalBitLen: bigint) {
    const mid = sha256Compress(this.initState, firstBlock);
    const final = sha256Finalize(mid, remaining, totalBitLen);
    const native = sha256(fullMessage);
    assert(final === native);
  }
}
`;

// ---- Helpers ----

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

/** Compute SHA-256 using Node.js crypto (the ultimate oracle). */
function nodeSha256(msgHex: string): string {
  return createHash('sha256')
    .update(Buffer.from(msgHex, 'hex'))
    .digest('hex');
}

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

// ---- Tests ----

describe('sha256Finalize — script execution', () => {
  describe('hardcoded known hashes', () => {
    it('SHA-256("abc") via finalize', () => {
      const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_SOURCE,
        { expected },
        'Sha256FinalizeTest.runar.ts',
      );
      // remaining = "abc" (3 bytes), msgBitLen = 24
      const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
      expect(result.success).toBe(true);
    });

    it('SHA-256("") via finalize', () => {
      const expected = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_SOURCE,
        { expected },
        'Sha256FinalizeTest.runar.ts',
      );
      // remaining = "" (0 bytes), msgBitLen = 0
      const result = contract.execute('verify', [SHA256_INIT, '', 0n]);
      expect(result.success).toBe(true);
    });

    it('rejects wrong expected hash', () => {
      const expected = '0000000000000000000000000000000000000000000000000000000000000000';

      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_SOURCE,
        { expected },
        'Sha256FinalizeTest.runar.ts',
      );
      const result = contract.execute('verify', [SHA256_INIT, '616263', 24n]);
      expect(result.success).toBe(false);
    });
  });

  describe('cross-verified against OP_SHA256 (single-block, remaining <= 55 bytes)', () => {
    const testMessages = [
      { name: 'empty', hex: '', bits: 0n },
      { name: '"abc"', hex: '616263', bits: 24n },
      { name: '1 byte (0x42)', hex: '42', bits: 8n },
      { name: '55 bytes (max single-block)', hex: 'aa'.repeat(55), bits: 440n },
      { name: '"Hello, SHA-256!"', hex: Buffer.from('Hello, SHA-256!').toString('hex'), bits: BigInt(Buffer.from('Hello, SHA-256!').length * 8) },
    ];

    for (const { name, hex, bits } of testMessages) {
      it(`message: ${name}`, () => {
        // Sanity: verify against Node.js crypto
        const nodeHash = nodeSha256(hex);

        const contract = ScriptExecutionContract.fromSource(
          SHA256_FINALIZE_CROSS_VERIFY_SOURCE,
          { initState: SHA256_INIT },
          'Sha256FinalizeCrossVerify.runar.ts',
        );

        const result = contract.execute('verify', [hex, bits]);
        if (!result.success) {
          console.log(`Cross-verify ${name} FAILED:`, result.error);
          console.log(`Expected (node crypto): ${nodeHash}`);
        }
        expect(result.success).toBe(true);
      });
    }
  });

  describe('cross-verified against OP_SHA256 (two-block, 56 <= remaining <= 119 bytes)', () => {
    const testMessages = [
      { name: '56 bytes (min two-block)', hex: 'bb'.repeat(56), bits: 448n },
      { name: '64 bytes', hex: 'cc'.repeat(64), bits: 512n },
      { name: '100 bytes', hex: 'dd'.repeat(100), bits: 800n },
    ];

    for (const { name, hex, bits } of testMessages) {
      it(`message: ${name}`, () => {
        const nodeHash = nodeSha256(hex);

        const contract = ScriptExecutionContract.fromSource(
          SHA256_FINALIZE_CROSS_VERIFY_SOURCE,
          { initState: SHA256_INIT },
          'Sha256FinalizeCrossVerify.runar.ts',
        );

        const result = contract.execute('verify', [hex, bits]);
        if (!result.success) {
          console.log(`Two-block finalize ${name} FAILED:`, result.error);
          console.log(`Expected (node crypto): ${nodeHash}`);
        }
        expect(result.success).toBe(true);
      });
    }
  });

  describe('chained: sha256Compress + sha256Finalize', () => {
    it('120-byte message: compress first 64 bytes, finalize remaining 56', () => {
      const fullMsg = 'ee'.repeat(120);
      const firstBlock = fullMsg.substring(0, 128); // first 64 bytes (128 hex chars)
      const remaining = fullMsg.substring(128);      // remaining 56 bytes
      const totalBitLen = 960n;                       // 120 * 8

      const nodeHash = nodeSha256(fullMsg);

      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_CHAINED_SOURCE,
        { initState: SHA256_INIT },
        'Sha256FinalizeChained.runar.ts',
      );

      const result = contract.execute('verify', [fullMsg, firstBlock, remaining, totalBitLen]);
      if (!result.success) {
        console.log('Chained finalize FAILED:', result.error);
        console.log(`Expected (node crypto): ${nodeHash}`);
      }
      expect(result.success).toBe(true);
    });
  });

  describe('non-initial state finalize', () => {
    it('finalize with intermediate state from prior compression', () => {
      // Simulate a 74-byte message: compress first 64 bytes, finalize remaining 10
      const block1Msg = 'ab'.repeat(64);
      const remainingMsg = 'cd'.repeat(10);
      const fullMsg = block1Msg + remainingMsg;
      const totalBitLen = 592n; // 74 * 8

      // Compute midState using our reference implementation
      const paddedBlock1 = block1Msg; // exactly 64 bytes, no SHA-256 padding here
      const midState = referenceSha256Compress(SHA256_INIT, paddedBlock1);

      // Expected: SHA-256 of the full 74-byte message
      const nodeHash = nodeSha256(fullMsg);

      // Use the basic finalize contract with the computed expected hash
      const contract = ScriptExecutionContract.fromSource(
        SHA256_FINALIZE_SOURCE,
        { expected: nodeHash },
        'Sha256FinalizeTest.runar.ts',
      );

      const result = contract.execute('verify', [midState, remainingMsg, totalBitLen]);
      if (!result.success) {
        console.log('Non-initial state finalize FAILED:', result.error);
        console.log(`midState: ${midState}`);
        console.log(`Expected (node crypto): ${nodeHash}`);
      }
      expect(result.success).toBe(true);
    });
  });
});
