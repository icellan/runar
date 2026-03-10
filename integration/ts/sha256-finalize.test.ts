/**
 * SHA-256 finalize integration tests — sha256Finalize on a real regtest node.
 *
 * sha256Finalize(state, remaining, msgBitLen) applies SHA-256 padding on-chain
 * and compresses 1 or 2 blocks. Tests cross-verify against OP_SHA256.
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

/**
 * Cross-verify: sha256Finalize(init, message, bitLen) === sha256(message)
 * The contract computes the hash via on-chain padding + compression,
 * then compares against the native OP_SHA256 opcode.
 */
const FINALIZE_CROSS_VERIFY = `
import { SmartContract, assert, sha256Finalize, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256FinalizeCross extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, msgBitLen: bigint) {
    const computed = sha256Finalize(this.initState, message, msgBitLen);
    const native = sha256(message);
    assert(computed === native);
  }
}
`;

/**
 * Two-step finalize: sha256Compress first block, then sha256Finalize on the rest.
 * Tests chaining of partial SHA-256 with finalization.
 */
const FINALIZE_CHAINED = `
import { SmartContract, assert, sha256Compress, sha256Finalize, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256FinalizeChained extends SmartContract {
  readonly initState: ByteString;

  constructor(initState: ByteString) {
    super(initState);
    this.initState = initState;
  }

  public verify(message: ByteString, firstBlock: ByteString, remaining: ByteString, msgBitLen: bigint) {
    const mid = sha256Compress(this.initState, firstBlock);
    const computed = sha256Finalize(mid, remaining, msgBitLen);
    const native = sha256(message);
    assert(computed === native);
  }
}
`;

describe('SHA-256 Finalize', () => {
  describe('single-block messages (remaining ≤ 55 bytes)', () => {
    const testCases = [
      { name: '"abc" (3 bytes)', hex: '616263', bits: 24n },
      { name: 'empty (0 bytes)', hex: '', bits: 0n },
      { name: '1 byte', hex: '42', bits: 8n },
      { name: '55 bytes (max single-block)', hex: 'aa'.repeat(55), bits: 440n },
    ];

    for (const { name, hex, bits } of testCases) {
      it(`cross-verifies: ${name}`, async () => {
        const artifact = compileSource(FINALIZE_CROSS_VERIFY, 'Sha256FinalizeCross.runar.ts');
        const contract = new RunarContract(artifact, [SHA256_INIT]);

        const provider = createProvider();
        const { signer } = await createFundedWallet(provider);

        await contract.deploy(provider, signer, { satoshis: 1000000 });

        const { txid } = await contract.call(
          'verify', [hex, bits], provider, signer,
        );
        expect(txid).toBeTruthy();
        expect(txid.length).toBe(64);
      });
    }
  });

  describe('two-block messages (56 ≤ remaining ≤ 119 bytes)', () => {
    const testCases = [
      { name: '56 bytes (min two-block)', hex: 'bb'.repeat(56), bits: 448n },
      { name: '64 bytes', hex: 'cc'.repeat(64), bits: 512n },
      { name: '100 bytes', hex: 'dd'.repeat(100), bits: 800n },
    ];

    for (const { name, hex, bits } of testCases) {
      it(`cross-verifies: ${name}`, async () => {
        const artifact = compileSource(FINALIZE_CROSS_VERIFY, 'Sha256FinalizeCross.runar.ts');
        const contract = new RunarContract(artifact, [SHA256_INIT]);

        const provider = createProvider();
        const { signer } = await createFundedWallet(provider);

        await contract.deploy(provider, signer, { satoshis: 1000000 });

        const { txid } = await contract.call(
          'verify', [hex, bits], provider, signer,
        );
        expect(txid).toBeTruthy();
        expect(txid.length).toBe(64);
      });
    }
  });

  describe('chained: sha256Compress + sha256Finalize', () => {
    it('120-byte message: compress first 64 bytes, finalize last 56', async () => {
      const msgHex = 'ee'.repeat(120);
      const firstBlock = msgHex.substring(0, 128); // first 64 bytes = 128 hex chars
      const remaining = msgHex.substring(128);      // last 56 bytes
      const bits = 960n; // 120 * 8

      const artifact = compileSource(FINALIZE_CHAINED, 'Sha256FinalizeChained.runar.ts');
      const contract = new RunarContract(artifact, [SHA256_INIT]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      await contract.deploy(provider, signer, { satoshis: 1000000 });

      const { txid } = await contract.call(
        'verify', [msgHex, firstBlock, remaining, bits], provider, signer,
      );
      expect(txid).toBeTruthy();
      expect(txid.length).toBe(64);
    });
  });
});
