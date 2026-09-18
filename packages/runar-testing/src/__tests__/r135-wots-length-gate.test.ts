/**
 * R-135 — `verifyWOTS` had no signature-length gate.
 *
 * The emitted verifier consumes the signature 32 bytes at a time with OP_SPLIT,
 * 67 times, then DROPPED whatever was left over ("drop empty sigRest" — without
 * checking it was empty). So `sig || junk` verified identically to `sig`, for
 * unbounded attacker-chosen junk. The reference implementation in
 * `crypto/wots.ts` has always rejected a wrong-length signature, so this was a
 * live divergence between the two oracles, not a shared design decision.
 *
 * Everything here is asserted on EXECUTED behaviour: `ScriptExecutionContract`
 * runs the compiled locking script on @bsv/sdk's `Spend` interpreter. Comparing
 * hex to hex would only prove the seven tiers agree, not that they are right.
 */
import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { ScriptExecutionContract } from '../script-execution.js';
import { wotsKeygen, wotsSign, WOTS_PARAMS } from '../crypto/wots.js';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

const PQ_WALLET_SOURCE = `
class PQWallet extends SmartContract {
  readonly pubkey: ByteString;
  constructor(pubkey: ByteString) {
    super(pubkey);
    this.pubkey = pubkey;
  }
  public spend(msg: ByteString, sig: ByteString) {
    assert(verifyWOTS(msg, sig, this.pubkey));
  }
}
`;

describe('R-135: verifyWOTS enforces the exact signature length', () => {
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const pubSeed = new Uint8Array(32);
  pubSeed[0] = 0x01;
  const { sk, pk } = wotsKeygen(seed, pubSeed);
  const pkHex = toHex(pk);

  const msg = new TextEncoder().encode('r135 length gate');
  const msgHex = toHex(msg);
  const sig = wotsSign(msg, sk, pubSeed);

  const compiled = ScriptExecutionContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex });
  const runScript = (sigBytes: Uint8Array) =>
    compiled.execute('spend', [msgHex, toHex(sigBytes)]);
  const runInterp = (sigBytes: Uint8Array) =>
    TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex })
      .call('spend', { msg: msgHex, sig: toHex(sigBytes) });

  const padded = (extra: number, fill = 0x00) => {
    const p = new Uint8Array(sig.length + extra);
    p.set(sig, 0);
    p.fill(fill, sig.length);
    return p;
  };

  // --- CONTROL. An over-strict gate would redden here, not in the attack cases.
  it('CONTROL: a genuine, correctly-sized signature still verifies', () => {
    expect(sig.length).toBe(WOTS_PARAMS.LEN * WOTS_PARAMS.N); // 67 * 32 = 2144
    expect(runInterp(sig).success).toBe(true);
    expect(runScript(sig).success).toBe(true);
  });

  it('CONTROL: the gate is the only thing rejecting — a real sig for a second message verifies', () => {
    const msg2 = new TextEncoder().encode('a different message entirely');
    const sig2 = wotsSign(msg2, sk, pubSeed);
    const c2 = ScriptExecutionContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex });
    expect(c2.execute('spend', [toHex(msg2), toHex(sig2)]).success).toBe(true);
  });

  it('rejects sig || 0x00 (the filed one-byte case)', () => {
    expect(runScript(padded(1)).success).toBe(false);
    expect(runInterp(padded(1)).success).toBe(false);
  });

  it('rejects sig || one attacker-chosen 0xff byte', () => {
    expect(runScript(padded(1, 0xff)).success).toBe(false);
  });

  it('rejects sig || 4096 junk bytes — the padding is unbounded, so the gate must be exact', () => {
    expect(runScript(padded(4096, 0xab)).success).toBe(false);
    expect(runInterp(padded(4096, 0xab)).success).toBe(false);
  });

  it('rejects a signature one whole chain element too long', () => {
    expect(runScript(padded(WOTS_PARAMS.N)).success).toBe(false);
  });

  it('still rejects short signatures (OP_SPLIT already aborted; the gate must not regress that)', () => {
    expect(runScript(sig.slice(0, sig.length - 1)).success).toBe(false);
    expect(runScript(sig.slice(0, sig.length - WOTS_PARAMS.N)).success).toBe(false);
  });

  // --- What the padding does NOT buy an attacker. Measured, not assumed:
  // the verdict is a pure function of the first 2144 bytes, so appending bytes
  // can never rescue a bad signature. The gain was malleability only.
  it('padding never rescued an invalid signature, before or after the gate', () => {
    const tampered = new Uint8Array(sig);
    tampered[0]! ^= 0xff;
    expect(runScript(tampered).success).toBe(false);
    const tamperedPadded = new Uint8Array(tampered.length + 1);
    tamperedPadded.set(tampered, 0);
    expect(runScript(tamperedPadded).success).toBe(false);
  });

  it('padding never let a signature verify against a different message', () => {
    const otherMsg = toHex(new TextEncoder().encode('not the signed message'));
    const c = ScriptExecutionContract.fromSource(PQ_WALLET_SOURCE, { pubkey: pkHex });
    expect(c.execute('spend', [otherMsg, toHex(sig)]).success).toBe(false);
    expect(c.execute('spend', [otherMsg, toHex(padded(1))]).success).toBe(false);
  });
});
