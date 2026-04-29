import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, slhKeygen, slhSign, SLH_SHA2_128s } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumSLHDSANaiveInsecure.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// PEDAGOGY: this contract is intentionally broken — see contract header.
// `verifySLHDSA_SHA2_128s(msg, sig, pubkey)` only checks that `sig` is a valid
// SLH-DSA signature over `msg` under `pubkey`. Because `msg` is a free
// unlocking-script argument with no link to the spending tx, anyone with ANY
// valid (msg, sig) triple under that pubkey can satisfy the script.
describe('PostQuantumSLHDSANaiveInsecure', () => {
  const params = SLH_SHA2_128s;
  const slhSeed = new Uint8Array(3 * params.n);
  slhSeed[0] = 0x42;
  const { sk, pk } = slhKeygen(params, slhSeed);
  const pubkeyHex = toHex(pk);

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    expect(c.state.pubkey).toBe(pubkeyHex);
  });

  it('FLAW: accepts an arbitrary msg not bound to any tx', () => {
    const arbitraryMsg = new Uint8Array(32);
    arbitraryMsg[0] = 0xAB;
    arbitraryMsg[1] = 0xCD;
    const sig = slhSign(params, arbitraryMsg, sk);

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    const r = c.call('spend', {
      msg: toHex(arbitraryMsg),
      sig: toHex(sig),
    });
    // This passing IS the bug — `msg` should be bound to the tx sighash.
    expect(r.success).toBe(true);
  });

  it('FLAW: any caller can re-sign a different message and spend', () => {
    const otherMsg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) otherMsg[i] = 0xff - i;
    const otherSig = slhSign(params, otherMsg, sk);

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    const r = c.call('spend', {
      msg: toHex(otherMsg),
      sig: toHex(otherSig),
    });
    expect(r.success).toBe(true);
  });

  it('still rejects a tampered signature (basic soundness)', () => {
    const msg = new Uint8Array(32);
    msg[0] = 0x99;
    const sig = slhSign(params, msg, sk);
    const tampered = new Uint8Array(sig);
    tampered[params.n + 10] ^= 0xff;

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    const r = c.call('spend', {
      msg: toHex(msg),
      sig: toHex(tampered),
    });
    expect(r.success).toBe(false);
  });
});
