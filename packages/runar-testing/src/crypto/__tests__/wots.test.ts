import { describe, it, expect } from 'vitest';
import { wotsKeygen, wotsSign, wotsVerify, WOTS_PARAMS } from '../wots.js';

const { LEN, N } = WOTS_PARAMS;

describe('WOTS+ reference implementation', () => {
  const seed = new Uint8Array(32);
  seed[0] = 0x42;
  const { sk, pk } = wotsKeygen(seed);

  describe('keygen', () => {
    it('generates correct number of secret key elements', () => {
      expect(sk.length).toBe(LEN); // 67
    });

    it('generates 32-byte secret key elements', () => {
      for (const s of sk) {
        expect(s.length).toBe(N); // 32
      }
    });

    it('generates a 32-byte public key', () => {
      expect(pk.length).toBe(N); // 32
    });

    it('is deterministic with same seed', () => {
      const { pk: pk2 } = wotsKeygen(seed);
      expect(pk2).toEqual(pk);
    });

    it('produces different keys with different seeds', () => {
      const otherSeed = new Uint8Array(32);
      otherSeed[0] = 0x99;
      const { pk: pk2 } = wotsKeygen(otherSeed);
      expect(pk2).not.toEqual(pk);
    });
  });

  describe('sign + verify round-trip', () => {
    const msg = new TextEncoder().encode('hello world');
    const sig = wotsSign(msg, sk);

    it('produces correct signature size', () => {
      expect(sig.length).toBe(LEN * N); // 67 * 32 = 2,144
    });

    it('verifies a valid signature', () => {
      expect(wotsVerify(msg, sig, pk)).toBe(true);
    });

    it('verifies different messages with same key', () => {
      const msg2 = new TextEncoder().encode('different message');
      const sig2 = wotsSign(msg2, sk);
      expect(wotsVerify(msg2, sig2, pk)).toBe(true);
    });
  });

  describe('rejection', () => {
    const msg = new TextEncoder().encode('test message');
    const sig = wotsSign(msg, sk);

    it('rejects a tampered signature (flipped byte)', () => {
      const bad = new Uint8Array(sig);
      bad[0]! ^= 0xff;
      expect(wotsVerify(msg, bad, pk)).toBe(false);
    });

    it('rejects a tampered signature (middle byte)', () => {
      const bad = new Uint8Array(sig);
      bad[1072]! ^= 0x01; // flip a bit in a middle chain element
      expect(wotsVerify(msg, bad, pk)).toBe(false);
    });

    it('rejects a tampered message', () => {
      const otherMsg = new TextEncoder().encode('tampered message');
      expect(wotsVerify(otherMsg, sig, pk)).toBe(false);
    });

    it('rejects wrong public key', () => {
      const otherSeed = new Uint8Array(32);
      otherSeed[0] = 0xaa;
      const { pk: otherPk } = wotsKeygen(otherSeed);
      expect(wotsVerify(msg, sig, otherPk)).toBe(false);
    });

    it('rejects truncated signature', () => {
      const truncated = sig.slice(0, sig.length - 1);
      expect(wotsVerify(msg, truncated, pk)).toBe(false);
    });

    it('rejects empty signature', () => {
      expect(wotsVerify(msg, new Uint8Array(0), pk)).toBe(false);
    });

    it('rejects wrong-length public key', () => {
      expect(wotsVerify(msg, sig, pk.slice(0, 16))).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('handles empty message', () => {
      const emptyMsg = new Uint8Array(0);
      const sig = wotsSign(emptyMsg, sk);
      expect(wotsVerify(emptyMsg, sig, pk)).toBe(true);
    });

    it('handles large message', () => {
      const largeMsg = new Uint8Array(10_000);
      largeMsg.fill(0xab);
      const sig = wotsSign(largeMsg, sk);
      expect(wotsVerify(largeMsg, sig, pk)).toBe(true);
    });

    it('random keypair round-trip (no seed)', () => {
      const { sk: rsk, pk: rpk } = wotsKeygen();
      const msg = new TextEncoder().encode('random key test');
      const sig = wotsSign(msg, rsk);
      expect(wotsVerify(msg, sig, rpk)).toBe(true);
    });
  });
});
