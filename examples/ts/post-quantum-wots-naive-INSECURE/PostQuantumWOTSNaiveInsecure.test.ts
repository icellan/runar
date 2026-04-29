import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract, wotsKeygen, wotsSign } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumWOTSNaiveInsecure.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

// PEDAGOGY: this contract is intentionally broken — see contract header.
// `verifyWOTS(msg, sig, pubkey)` only checks that `sig` is a valid WOTS+
// signature over `msg` under `pubkey`. Because `msg` is a free unlocking-script
// argument with no link to the spending tx, anyone with ANY valid (msg, sig)
// triple under that pubkey can satisfy the script. These tests pin that
// behaviour into the test record so future refactors don't accidentally hide
// the flaw.
describe('PostQuantumWOTSNaiveInsecure', () => {
  // WOTS+ keypair.
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const pubSeed = new Uint8Array(32);
  pubSeed[0] = 0x01;
  const { sk, pk } = wotsKeygen(seed, pubSeed);
  const pubkeyHex = toHex(pk);

  it('compiles via TestContract.fromSource', () => {
    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    expect(c.state.pubkey).toBe(pubkeyHex);
  });

  it('FLAW: accepts an arbitrary msg not bound to any tx', () => {
    // The `msg` here is plain bytes the spender chose freely. It has no
    // relationship to the transaction being authorised.
    const arbitraryMsg = new Uint8Array(32);
    arbitraryMsg[0] = 0xAB;
    arbitraryMsg[1] = 0xCD;
    const sig = wotsSign(arbitraryMsg, sk, pubSeed);

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    const r = c.call('spend', {
      msg: toHex(arbitraryMsg),
      sig: toHex(sig),
    });
    // This passing IS the bug — the contract should bind `msg` to the tx.
    expect(r.success).toBe(true);
  });

  it('FLAW: a different arbitrary msg with its own valid sig also passes', () => {
    // Demonstrates "anyone can spend" given any valid (msg, sig) pair: the
    // contract has no notion of which message is the right one.
    const otherMsg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) otherMsg[i] = i; // 00 01 02 ... 1f
    const otherSig = wotsSign(otherMsg, sk, pubSeed);

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
    const sig = wotsSign(msg, sk, pubSeed);
    const tampered = new Uint8Array(sig);
    tampered[10] ^= 0xff;

    const c = TestContract.fromSource(source, { pubkey: pubkeyHex });
    const r = c.call('spend', {
      msg: toHex(msg),
      sig: toHex(tampered),
    });
    expect(r.success).toBe(false);
  });
});
