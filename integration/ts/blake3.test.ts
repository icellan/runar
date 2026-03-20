/**
 * BLAKE3 integration tests — inline contracts testing blake3Compress and
 * blake3Hash on a real regtest node.
 *
 * Each test compiles a minimal stateless contract, deploys on regtest, and spends
 * via contract.call(). The compiled script is ~11KB (BLAKE3 compression inlined),
 * validated by a real BSV node, not just the SDK interpreter.
 *
 * Tests include:
 *   - blake3Compress: known hash vectors, non-IV chaining value, rejection
 *   - blake3Hash: empty, "abc", 32-byte, 64-byte, rejection
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

// ---- BLAKE3 reference implementation ----

const BLAKE3_IV = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const BLAKE3_IV_HEX = BLAKE3_IV.map(w => w.toString(16).padStart(8, '0')).join('');
const MSG_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

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
function referenceBlake3Compress(cvHex: string, blockHex: string): string {
  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(parseInt(cvHex.substring(i * 8, i * 8 + 8), 16));
  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));

  const state: number[] = [
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0, 0, 64, 11,
  ];

  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    blake3Round(state, msg);
    if (r < 6) msg = MSG_PERM.map(i => msg[i]!);
  }

  const output: number[] = [];
  for (let i = 0; i < 8; i++) output.push((state[i]! ^ state[i + 8]!) >>> 0);
  return output.map(w => w.toString(16).padStart(8, '0')).join('');
}
function referenceBlake3Hash(msgHex: string): string {
  const padded = msgHex.padEnd(128, '0');
  return referenceBlake3Compress(BLAKE3_IV_HEX, padded);
}

// ---- Tests ----

describe('BLAKE3', () => {
  describe('blake3Compress', () => {
    it('deploy + spend: empty block with IV chaining value', async () => {
      const source = `
import { SmartContract, assert, blake3Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3CompressEmpty extends SmartContract {
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
      const block = '00'.repeat(64);
      const expected = referenceBlake3Compress(BLAKE3_IV_HEX, block);

      const artifact = compileSource(source, 'Blake3CompressEmpty.runar.ts');
      const contract = new RunarContract(artifact, [expected]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500000 });
      expect(deployTxid).toBeTruthy();

      const { txid } = await contract.call(
        'verify', [BLAKE3_IV_HEX, block], provider, signer,
      );
      expect(txid).toBeTruthy();
      expect(txid.length).toBe(64);
    });

    it('deploy + spend: "abc" padded to 64 bytes', async () => {
      const source = `
import { SmartContract, assert, blake3Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3CompressAbc extends SmartContract {
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
      const block = '616263' + '00'.repeat(61);
      const expected = referenceBlake3Compress(BLAKE3_IV_HEX, block);

      const artifact = compileSource(source, 'Blake3CompressAbc.runar.ts');
      const contract = new RunarContract(artifact, [expected]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      await contract.deploy(provider, signer, { satoshis: 500000 });

      const { txid } = await contract.call(
        'verify', [BLAKE3_IV_HEX, block], provider, signer,
      );
      expect(txid).toBeTruthy();
      expect(txid.length).toBe(64);
    });

    it('deploy + spend: non-IV chaining value', async () => {
      const source = `
import { SmartContract, assert, blake3Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3CompressNonIV extends SmartContract {
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
      const customCV = 'deadbeef'.repeat(8);
      const block = 'ff'.repeat(64);
      const expected = referenceBlake3Compress(customCV, block);

      const artifact = compileSource(source, 'Blake3CompressNonIV.runar.ts');
      const contract = new RunarContract(artifact, [expected]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      await contract.deploy(provider, signer, { satoshis: 500000 });

      const { txid } = await contract.call(
        'verify', [customCV, block], provider, signer,
      );
      expect(txid).toBeTruthy();
      expect(txid.length).toBe(64);
    });

    it('rejects wrong expected hash on-chain', async () => {
      const source = `
import { SmartContract, assert, blake3Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3CompressReject extends SmartContract {
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
      const block = '00'.repeat(64);
      const wrongExpected = '00'.repeat(32);

      const artifact = compileSource(source, 'Blake3CompressReject.runar.ts');
      const contract = new RunarContract(artifact, [wrongExpected]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      await contract.deploy(provider, signer, { satoshis: 500000 });

      await expect(
        contract.call('verify', [BLAKE3_IV_HEX, block], provider, signer),
      ).rejects.toThrow();
    });
  });

  describe('blake3Hash', () => {
    const hashTests = [
      { name: 'empty message', msgHex: '' },
      { name: '"abc"', msgHex: '616263' },
      { name: '32-byte message', msgHex: 'ab'.repeat(32) },
      { name: '64-byte message (full block)', msgHex: 'cd'.repeat(64) },
    ];

    for (const { name, msgHex } of hashTests) {
      it(`deploy + spend: ${name}`, async () => {
        const source = `
import { SmartContract, assert, blake3Hash } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3Hash${name.replace(/[^a-zA-Z0-9]/g, '')} extends SmartContract {
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
        const expected = referenceBlake3Hash(msgHex);
        const className = `Blake3Hash${name.replace(/[^a-zA-Z0-9]/g, '')}`;

        const artifact = compileSource(source, `${className}.runar.ts`);
        const contract = new RunarContract(artifact, [expected]);

        const provider = createProvider();
        const { signer } = await createFundedWallet(provider);

        await contract.deploy(provider, signer, { satoshis: 500000 });

        const { txid } = await contract.call(
          'verify', [msgHex], provider, signer,
        );
        expect(txid).toBeTruthy();
        expect(txid.length).toBe(64);
      });
    }

    it('rejects wrong expected hash on-chain', async () => {
      const source = `
import { SmartContract, assert, blake3Hash } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Blake3HashReject extends SmartContract {
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
      const wrongExpected = 'ff'.repeat(32);

      const artifact = compileSource(source, 'Blake3HashReject.runar.ts');
      const contract = new RunarContract(artifact, [wrongExpected]);

      const provider = createProvider();
      const { signer } = await createFundedWallet(provider);

      await contract.deploy(provider, signer, { satoshis: 500000 });

      await expect(
        contract.call('verify', ['616263'], provider, signer),
      ).rejects.toThrow();
    });
  });
});
