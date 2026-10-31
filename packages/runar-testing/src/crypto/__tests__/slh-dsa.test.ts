import { describe, it, expect } from 'vitest';
import {
  slhKeygen, slhSign, slhVerify,
  SLH_SHA2_128s, SLH_SHA2_128f,
  SLH_SHA2_192s, SLH_SHA2_256s,
} from '../slh-dsa.js';

describe('SLH-DSA reference implementation', () => {
  // Use a fixed seed for deterministic tests
  const seed128 = new Uint8Array(48); // 3*16 = 48 bytes for n=16
  seed128[0] = 0x42;

  describe('SLH-DSA-SHA2-128s', () => {
    const params = SLH_SHA2_128s;
    const { sk, pk } = slhKeygen(params, seed128);

    it('generates correct key sizes', () => {
      expect(sk.length).toBe(4 * params.n); // 64 bytes
      expect(pk.length).toBe(2 * params.n); // 32 bytes
    });

    it('is deterministic with same seed', () => {
      const { pk: pk2 } = slhKeygen(params, seed128);
      expect(pk2).toEqual(pk);
    });

    it('sign + verify round-trip', () => {
      const msg = new TextEncoder().encode('hello SLH-DSA');
      const sig = slhSign(params, msg, sk);

      // Check signature size: R + FORS + d * XMSS
      const forsLen = params.k * (1 + params.a) * params.n;
      const xmssLen = (params.len + params.hp) * params.n;
      const expectedLen = params.n + forsLen + params.d * xmssLen;
      expect(sig.length).toBe(expectedLen);

      expect(slhVerify(params, msg, sig, pk)).toBe(true);
    });

    it('rejects tampered signature', () => {
      const msg = new TextEncoder().encode('tamper test');
      const sig = slhSign(params, msg, sk);
      const badSig = new Uint8Array(sig);
      badSig[params.n + 1]! ^= 0xff; // flip a byte in FORS section
      expect(slhVerify(params, msg, badSig, pk)).toBe(false);
    });

    it('rejects wrong message', () => {
      const msg = new TextEncoder().encode('correct');
      const sig = slhSign(params, msg, sk);
      const wrong = new TextEncoder().encode('wrong');
      expect(slhVerify(params, wrong, sig, pk)).toBe(false);
    });

    it('rejects wrong public key', () => {
      const msg = new TextEncoder().encode('key test');
      const sig = slhSign(params, msg, sk);
      const otherSeed = new Uint8Array(48);
      otherSeed[0] = 0xaa;
      const { pk: otherPk } = slhKeygen(params, otherSeed);
      expect(slhVerify(params, msg, sig, otherPk)).toBe(false);
    });
  });

  // Spot-check other parameter sets (sign+verify is slow, so just verify key sizes + round-trip)
  describe('SLH-DSA-SHA2-128f (spot check)', () => {
    it('keygen + sign + verify round-trip', () => {
      const params = SLH_SHA2_128f;
      const seed = new Uint8Array(48);
      seed[0] = 0x11;
      const { sk, pk } = slhKeygen(params, seed);
      expect(pk.length).toBe(2 * params.n);
      const msg = new TextEncoder().encode('128f');
      const sig = slhSign(params, msg, sk);
      expect(slhVerify(params, msg, sig, pk)).toBe(true);
    });
  });

  describe('SLH-DSA-SHA2-192s (spot check)', () => {
    it('keygen produces correct sizes', () => {
      const params = SLH_SHA2_192s;
      const seed = new Uint8Array(72); // 3*24
      seed[0] = 0x22;
      const { sk, pk } = slhKeygen(params, seed);
      expect(sk.length).toBe(4 * params.n); // 96
      expect(pk.length).toBe(2 * params.n); // 48
    });
  });

  describe('SLH-DSA-SHA2-256s (spot check)', () => {
    it('keygen produces correct sizes', () => {
      const params = SLH_SHA2_256s;
      const seed = new Uint8Array(96); // 3*32
      seed[0] = 0x33;
      const { sk, pk } = slhKeygen(params, seed);
      expect(sk.length).toBe(4 * params.n); // 128
      expect(pk.length).toBe(2 * params.n); // 64
    });
  });
});
