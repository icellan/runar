import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, slhKeygen, slhSign, SLH_SHA2_128s } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumSLHDSANaiveInsecure.runar.sol'), 'utf8');
const FILE_NAME = 'PostQuantumSLHDSANaiveInsecure.runar.sol';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// PEDAGOGY: this contract is intentionally broken — see contract header.
describe('PostQuantumSLHDSANaiveInsecure (Solidity)', () => {
  const params = SLH_SHA2_128s;
  const slhSeed = new Uint8Array(3 * params.n);
  slhSeed[0] = 0x42;
  const { sk, pk } = slhKeygen(params, slhSeed);
  const pubkeyHex = toHex(pk);

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    expect(c.state.pubkey).toBe(pubkeyHex);
  });

  it('FLAW: accepts an arbitrary msg not bound to any tx', () => {
    const arbitraryMsg = new Uint8Array(32);
    arbitraryMsg[0] = 0xAB;
    arbitraryMsg[1] = 0xCD;
    const sig = slhSign(params, arbitraryMsg, sk);

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    const r = c.call('spend', { msg: toHex(arbitraryMsg), sig: toHex(sig) });
    expect(r.success).toBe(true);
  });

  it('still rejects a tampered signature (basic soundness)', () => {
    const msg = new Uint8Array(32);
    msg[0] = 0x99;
    const sig = slhSign(params, msg, sk);
    const tampered = new Uint8Array(sig);
    tampered[params.n + 10] ^= 0xff;

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex }, FILE_NAME);
    const r = c.call('spend', { msg: toHex(msg), sig: toHex(tampered) });
    expect(r.success).toBe(false);
  });
});
