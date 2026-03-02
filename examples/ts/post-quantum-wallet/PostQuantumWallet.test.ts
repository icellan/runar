import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';
// Import directly from the source path (vitest resolves via alias)
import { wotsKeygen, wotsSign } from '../../../packages/runar-testing/src/crypto/wots.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumWallet.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const seed = new Uint8Array(32);
seed[0] = 0x42;
const { sk, pk } = wotsKeygen(seed);

describe('PostQuantumWallet (WOTS+)', () => {
  it('accepts a valid WOTS+ signature', () => {
    const msg = new TextEncoder().encode('spend this UTXO');
    const sig = wotsSign(msg, sk);
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(true);
  });

  it('rejects an invalid signature', () => {
    const msg = new TextEncoder().encode('spend this UTXO');
    const sig = wotsSign(msg, sk);
    const tampered = new Uint8Array(sig);
    tampered[100]! ^= 0xff;
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
    expect(result.success).toBe(false);
  });

  it('rejects a wrong message', () => {
    const msg = new TextEncoder().encode('original message');
    const sig = wotsSign(msg, sk);
    const wrong = new TextEncoder().encode('different message');
    const contract = TestContract.fromSource(source, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(wrong), sig: toHex(sig) });
    expect(result.success).toBe(false);
  });
});
