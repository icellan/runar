import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, wotsKeygen, wotsSign } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumWOTSNaiveInsecure.runar.move'), 'utf8');
const FILE_NAME = 'PostQuantumWOTSNaiveInsecure.runar.move';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// PEDAGOGY: this contract is intentionally broken — see contract header.
describe('PostQuantumWOTSNaiveInsecure (Move)', () => {
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const pubSeed = new Uint8Array(32);
  pubSeed[0] = 0x01;
  const { sk, pk } = wotsKeygen(seed, pubSeed);
  const pubkeyHex = toHex(pk);

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    expect(c.state.pubkey).toBe(pubkeyHex);
  });

  it('FLAW: accepts an arbitrary msg not bound to any tx', () => {
    const arbitraryMsg = new Uint8Array(32);
    arbitraryMsg[0] = 0xAB;
    arbitraryMsg[1] = 0xCD;
    const sig = wotsSign(arbitraryMsg, sk, pubSeed);

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    const r = c.call('spend', { msg: toHex(arbitraryMsg), sig: toHex(sig) });
    expect(r.success).toBe(true);
  });

  it('still rejects a tampered signature (basic soundness)', () => {
    const msg = new Uint8Array(32);
    msg[0] = 0x99;
    const sig = wotsSign(msg, sk, pubSeed);
    const tampered = new Uint8Array(sig);
    tampered[10] ^= 0xff;

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    const r = c.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
    expect(r.success).toBe(false);
  });
});
