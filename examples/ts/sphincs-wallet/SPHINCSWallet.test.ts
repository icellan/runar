import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
import {
  slhKeygen, slhSign, SLH_SHA2_128s,
} from '../../../packages/runar-testing/src/crypto/slh-dsa.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'SPHINCSWallet.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const params = SLH_SHA2_128s;
const seed = new Uint8Array(3 * params.n);
seed[0] = 0x42;
const { sk, pk } = slhKeygen(params, seed);

describe('SPHINCSWallet (SLH-DSA-SHA2-128s)', () => {
  it('accepts a valid SLH-DSA signature', () => {
    const msg = new TextEncoder().encode('spend this UTXO');
    const sig = slhSign(params, msg, sk);
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered signature', () => {
    const msg = new TextEncoder().encode('spend this UTXO');
    const sig = slhSign(params, msg, sk);
    const tampered = new Uint8Array(sig);
    tampered[params.n + 10]! ^= 0xff;
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
    expect(result.success).toBe(false);
  });

  it('rejects a wrong message', () => {
    const msg = new TextEncoder().encode('original message');
    const sig = slhSign(params, msg, sk);
    const wrong = new TextEncoder().encode('different message');
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(wrong), sig: toHex(sig) });
    expect(result.success).toBe(false);
  });

  it('accepts multiple signatures from same keypair (stateless)', () => {
    const msg1 = new TextEncoder().encode('first message');
    const msg2 = new TextEncoder().encode('second message');
    const sig1 = slhSign(params, msg1, sk);
    const sig2 = slhSign(params, msg2, sk);

    const contract1 = TestContract.fromSource(source, { pubkey: toHex(pk) });
    expect(contract1.call('spend', { msg: toHex(msg1), sig: toHex(sig1) }).success).toBe(true);

    const contract2 = TestContract.fromSource(source, { pubkey: toHex(pk) });
    expect(contract2.call('spend', { msg: toHex(msg2), sig: toHex(sig2) }).success).toBe(true);
  });
});
