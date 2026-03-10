/**
 * SHA-256 compression integration tests — inline contracts testing sha256Compress
 * on a real regtest node.
 *
 * Each test compiles a minimal stateless contract, deploys on regtest, and spends
 * via contract.call(). The compiled script is ~74KB (64 rounds × ~1000 ops each),
 * validated by a real BSV node, not just the SDK interpreter.
 *
 * Tests include:
 *   - Single-block: sha256Compress(init, padded) checked against hardcoded hash
 *   - Cross-verified: sha256Compress result compared against OP_SHA256 inside script
 *   - Two-block: chained sha256Compress calls for messages > 55 bytes
 *   - Non-initial state: compression starting from an arbitrary intermediate state
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { createHash } from 'crypto';

// ---- SHA-256 constants and helpers ----

const SHA256_INIT = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';

/** Pad a message (hex) to SHA-256 blocks per FIPS 180-4 Section 5.1.1. */
function sha256Pad(msgHex: string): string {
  const msgBytes = msgHex.length / 2;
  const bitLen = msgBytes * 8;
  let padded = msgHex + '80';
  while ((padded.length / 2) % 64 !== 56) padded += '00';
  padded += bitLen.toString(16).padStart(16, '0');
  return padded;
}

/** Reference SHA-256 compression (pure JS) for computing expected values. */
function referenceSha256Compress(stateHex: string, blockHex: string): string {
  const K = [
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
  const rotr = (x: number, n: number) => ((x >>> n) | (x << (32 - n))) >>> 0;
  const add = (a: number, b: number) => (a + b) >>> 0;

  const H: number[] = [];
  for (let i = 0; i < 8; i++) H.push(parseInt(stateHex.substring(i * 8, i * 8 + 8), 16));
  const W: number[] = [];
  for (let i = 0; i < 16; i++) W.push(parseInt(blockHex.substring(i * 8, i * 8 + 8), 16));
  for (let t = 16; t < 64; t++) {
    const s0 = (rotr(W[t-15]!, 7) ^ rotr(W[t-15]!, 18) ^ (W[t-15]! >>> 3)) >>> 0;
    const s1 = (rotr(W[t-2]!, 17) ^ rotr(W[t-2]!, 19) ^ (W[t-2]! >>> 10)) >>> 0;
    W.push(add(add(add(s1, W[t-7]!), s0), W[t-16]!));
  }
  let [a, b, c, d, e, f, g, h] = H;
  for (let t = 0; t < 64; t++) {
    const S1 = (rotr(e!, 6) ^ rotr(e!, 11) ^ rotr(e!, 25)) >>> 0;
    const ch = ((e! & f!) ^ (~e! & g!)) >>> 0;
    const T1 = add(add(add(add(h!, S1), ch), K[t]!), W[t]!);
    const S0 = (rotr(a!, 2) ^ rotr(a!, 13) ^ rotr(a!, 22)) >>> 0;
    const maj = ((a! & b!) ^ (a! & c!) ^ (b! & c!)) >>> 0;
    const T2 = add(S0, maj);
    h = g!; g = f!; f = e!; e = add(d!, T1);
    d = c!; c = b!; b = a!; a = add(T1, T2);
  }
  return [
    add(a!, H[0]!), add(b!, H[1]!), add(c!, H[2]!), add(d!, H[3]!),
    add(e!, H[4]!), add(f!, H[5]!), add(g!, H[6]!), add(h!, H[7]!),
  ].map(w => w.toString(16).padStart(8, '0')).join('');
}

// ---- Tests ----

describe('SHA-256 Compress', () => {
  it('single-block: sha256Compress produces correct SHA-256("abc")', async () => {
    const source = `
import { SmartContract, assert, sha256Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256AbcTest extends SmartContract {
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
    const artifact = compileSource(source, 'Sha256AbcTest.runar.ts');

    const block =
      '6162638000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000018';
    const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

    const contract = new RunarContract(artifact, [expected]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call(
      'verify', [SHA256_INIT, block], provider, signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('cross-verify: sha256Compress matches OP_SHA256 for "abc"', async () => {
    const source = `
import { SmartContract, assert, sha256Compress, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

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
    const artifact = compileSource(source, 'Sha256CrossVerify.runar.ts');
    const contract = new RunarContract(artifact, [SHA256_INIT]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    const msgHex = '616263'; // "abc"
    const padded = sha256Pad(msgHex);

    const { txid } = await contract.call(
      'verify', [msgHex, padded], provider, signer,
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('cross-verify: sha256Compress matches OP_SHA256 for 55-byte message', async () => {
    const source = `
import { SmartContract, assert, sha256Compress, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256CrossVerify55 extends SmartContract {
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
    const artifact = compileSource(source, 'Sha256CrossVerify55.runar.ts');
    const contract = new RunarContract(artifact, [SHA256_INIT]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    // 55 bytes is the maximum single-block message
    const msgHex = 'aa'.repeat(55);
    const padded = sha256Pad(msgHex);
    expect(padded.length / 2).toBe(64); // single block

    const { txid } = await contract.call(
      'verify', [msgHex, padded], provider, signer,
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('two-block: chained sha256Compress matches OP_SHA256 for 56-byte message', async () => {
    const source = `
import { SmartContract, assert, sha256Compress, sha256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

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
    const artifact = compileSource(source, 'Sha256TwoBlock.runar.ts');
    const contract = new RunarContract(artifact, [SHA256_INIT]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    // 56 bytes: shortest message requiring 2 SHA-256 blocks
    const msgHex = 'bb'.repeat(56);
    const padded = sha256Pad(msgHex);
    expect(padded.length / 2).toBe(128); // 2 blocks

    const block1 = padded.substring(0, 128);
    const block2 = padded.substring(128, 256);

    const { txid } = await contract.call(
      'verify', [msgHex, block1, block2], provider, signer,
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('non-initial state: compression with arbitrary intermediate state', async () => {
    const source = `
import { SmartContract, assert, sha256Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256NonInitial extends SmartContract {
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
    // Use SHA-256("abc") as intermediate state, compress a padded 10-byte message
    const midState = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
    const block = sha256Pad('ff'.repeat(10));
    const expected = referenceSha256Compress(midState, block);

    const artifact = compileSource(source, 'Sha256NonInitial.runar.ts');
    const contract = new RunarContract(artifact, [expected]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    const { txid } = await contract.call(
      'verify', [midState, block], provider, signer,
    );
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);
  });

  it('rejects wrong hash on-chain', async () => {
    const source = `
import { SmartContract, assert, sha256Compress } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class Sha256RejectWrong extends SmartContract {
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
    const block =
      '6162638000000000000000000000000000000000000000000000000000000000' +
      '0000000000000000000000000000000000000000000000000000000000000018';
    const wrongExpected = '0000000000000000000000000000000000000000000000000000000000000000';

    const artifact = compileSource(source, 'Sha256RejectWrong.runar.ts');
    const contract = new RunarContract(artifact, [wrongExpected]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500000 });

    // Should fail: wrong expected hash
    await expect(
      contract.call('verify', [SHA256_INIT, block], provider, signer),
    ).rejects.toThrow();
  });
});
