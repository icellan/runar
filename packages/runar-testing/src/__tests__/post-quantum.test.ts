import { describe, it, expect } from 'vitest';
import { TestContract } from '../test-contract.js';
import { wotsKeygen, wotsSign } from '../crypto/wots.js';

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

describe('WOTS+ verification via interpreter', () => {
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const { sk, pk } = wotsKeygen(seed);

  it('accepts a valid WOTS+ signature', () => {
    const msg = new TextEncoder().encode('hello world');
    const sig = wotsSign(msg, sk);
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered signature', () => {
    const msg = new TextEncoder().encode('hello world');
    const sig = wotsSign(msg, sk);
    const badSig = new Uint8Array(sig);
    badSig[0]! ^= 0xff;
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(badSig) });
    expect(result.success).toBe(false);
  });

  it('rejects a wrong message', () => {
    const msg = new TextEncoder().encode('correct message');
    const sig = wotsSign(msg, sk);
    const wrongMsg = new TextEncoder().encode('wrong message');
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: toHex(wrongMsg), sig: toHex(sig) });
    expect(result.success).toBe(false);
  });

  it('rejects a wrong public key', () => {
    const msg = new TextEncoder().encode('test');
    const sig = wotsSign(msg, sk);
    const otherSeed = new Uint8Array(32);
    otherSeed[0] = 0xaa;
    const { pk: otherPk } = wotsKeygen(otherSeed);
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(otherPk) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(false);
  });

  it('works with empty message', () => {
    const msg = new Uint8Array(0);
    const sig = wotsSign(msg, sk);
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(pk) });
    const result = contract.call('spend', { msg: '', sig: toHex(sig) });
    expect(result.success).toBe(true);
  });

  it('works with a different keypair', () => {
    const seed2 = new Uint8Array(32);
    seed2[0] = 0x99;
    const { sk: sk2, pk: pk2 } = wotsKeygen(seed2);
    const msg = new TextEncoder().encode('different key test');
    const sig = wotsSign(msg, sk2);
    const contract = TestContract.fromSource(PQ_WALLET_SOURCE, { pubkey: toHex(pk2) });
    const result = contract.call('spend', { msg: toHex(msg), sig: toHex(sig) });
    expect(result.success).toBe(true);
  });
});
