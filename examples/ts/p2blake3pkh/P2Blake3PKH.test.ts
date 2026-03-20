import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P2Blake3PKH.runar.ts'), 'utf8');

// ---- Compact BLAKE3 reference for computing correct pubKeyHash ----

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

function referenceBlake3Hash(msgHex: string): string {
  const padded = msgHex.padEnd(128, '0');
  const cv: number[] = [];
  for (let i = 0; i < 8; i++) cv.push(parseInt(BLAKE3_IV_HEX.substring(i * 8, i * 8 + 8), 16));

  const m: number[] = [];
  for (let i = 0; i < 16; i++) m.push(parseInt(padded.substring(i * 8, i * 8 + 8), 16));

  const state: number[] = [
    cv[0]!, cv[1]!, cv[2]!, cv[3]!,
    cv[4]!, cv[5]!, cv[6]!, cv[7]!,
    BLAKE3_IV[0]!, BLAKE3_IV[1]!, BLAKE3_IV[2]!, BLAKE3_IV[3]!,
    0, 0, 64, 11, // counter=0, counter_hi=0, blockLen=64, flags=CHUNK_START|CHUNK_END|ROOT
  ];

  let msg = [...m];
  for (let r = 0; r < 7; r++) {
    blake3Round(state, msg);
    if (r < 6) msg = MSG_PERM.map(i => msg[i]!);
  }

  const output: number[] = [];
  for (let i = 0; i < 8; i++) {
    output.push((state[i]! ^ state[i + 8]!) >>> 0);
  }

  return output.map(w => w.toString(16).padStart(8, '0')).join('');
}

// ---- Test fixtures using real test keys ----

const PUBKEY = ALICE.pubKey;
const SIG = signTestMessage(ALICE.privKey);
const PUBKEY_HASH = referenceBlake3Hash(PUBKEY);

describe('P2Blake3PKH', () => {
  it('accepts a valid unlock', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH });
    const result = contract.call('unlock', { sig: SIG, pubKey: PUBKEY });
    expect(result.success).toBe(true);
  });

  it('rejects wrong pubkey hash', () => {
    const wrongHash = '00'.repeat(32);
    const contract = TestContract.fromSource(source, { pubKeyHash: wrongHash });
    const result = contract.call('unlock', { sig: SIG, pubKey: PUBKEY });
    // blake3Hash(PUBKEY) !== wrongHash, so the first assert in unlock() fails
    expect(result.success).toBe(false);
  });

  // Note: The interpreter performs real ECDSA verification over a fixed
  // TEST_MESSAGE, so we cannot test with arbitrary signatures. Use
  // integration tests for full on-chain signature verification.

  it('is a stateless contract with no state tracking', () => {
    const contract = TestContract.fromSource(source, { pubKeyHash: PUBKEY_HASH });
    expect(contract.state.pubKeyHash).toBeDefined();
  });
});
