import { describe, it, expect } from 'vitest';
import { Hash, PrivateKey, Utils } from '@bsv/sdk';

import {
  computeNewState,
  executeStrict,
  executeOnChainAuthoritative,
  AssertionFailureError,
} from '../anf-interpreter.js';
import * as RunarSdk from '../index.js';
import type { ANFProgram } from 'runar-ir-schema';

// ---------------------------------------------------------------------------
// Real-crypto mode: executeOnChainAuthoritative.
//
// Asserts the third execution mode actually does ECDSA + SHA-256 preimage
// verification against a caller-supplied sighash, and that the existing
// lenient + strict modes still mock crypto so they don't regress.
// ---------------------------------------------------------------------------

const TEST_PRIV_HEX =
  // Deterministic test private key (not a real key — fixture only).
  'aa11bb22cc33dd44ee55ff667788990011223344556677889900aabbccddeeff';

function deterministicSighash(): number[] {
  // Any 32-byte digest will do for this test — the on-chain VM doesn't
  // care how the sighash was derived, only that signatures verify against
  // it. We pick `SHA256("runar-sdk-anf-real-crypto-test")` for reproducibility.
  return Hash.sha256(
    Utils.toArray('runar-sdk-anf-real-crypto-test', 'utf8'),
  );
}

function makeP2PKHGuardANF(): ANFProgram {
  // Stateful Guard{ value }: unlock(sig, pk) calls checkSig and asserts on it,
  // then bumps `value` to 1. On-chain, this fails when the signature is
  // garbage; in lenient + strict modes (where checkSig is mocked) it passes
  // regardless.
  return {
    contractName: 'Guard',
    properties: [{ name: 'value', type: 'bigint', readonly: false }],
    methods: [{
      name: 'unlock',
      params: [
        { name: 'sig', type: 'Sig' },
        { name: 'pk', type: 'PubKey' },
      ],
      body: [
        { name: 'sigArg', value: { kind: 'load_param', name: 'sig' } },
        { name: 'pkArg', value: { kind: 'load_param', name: 'pk' } },
        { name: 'sigOk', value: { kind: 'call', func: 'checkSig', args: ['sigArg', 'pkArg'] } },
        { name: 'assertSig', value: { kind: 'assert', value: 'sigOk' } },
        { name: 'one', value: { kind: 'load_const', value: 1n } },
        { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
      ],
      isPublic: true,
    }],
  };
}

function makePreimageGuardANF(): ANFProgram {
  // unlock(preimage): assert(checkPreimage(preimage)); value = 1.
  return {
    contractName: 'PreimageGuard',
    properties: [{ name: 'value', type: 'bigint', readonly: false }],
    methods: [{
      name: 'unlock',
      params: [{ name: 'preimage', type: 'SigHashPreimage' }],
      body: [
        { name: 'pre', value: { kind: 'load_param', name: 'preimage' } },
        { name: 'preOk', value: { kind: 'call', func: 'checkPreimage', args: ['pre'] } },
        { name: 'assertPre', value: { kind: 'assert', value: 'preOk' } },
        { name: 'one', value: { kind: 'load_const', value: 1n } },
        { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
      ],
      isPublic: true,
    }],
  };
}

function makeMultisigGuardANF(): ANFProgram {
  // unlock(sigs, pks): assert(checkMultiSig(sigs, pks)); value = 1.
  return {
    contractName: 'MultisigGuard',
    properties: [{ name: 'value', type: 'bigint', readonly: false }],
    methods: [{
      name: 'unlock',
      params: [
        { name: 'sigs', type: 'Sig[]' },
        { name: 'pks', type: 'PubKey[]' },
      ],
      body: [
        { name: 'sigsArg', value: { kind: 'load_param', name: 'sigs' } },
        { name: 'pksArg', value: { kind: 'load_param', name: 'pks' } },
        { name: 'msigOk', value: { kind: 'call', func: 'checkMultiSig', args: ['sigsArg', 'pksArg'] } },
        { name: 'assertMsig', value: { kind: 'assert', value: 'msigOk' } },
        { name: 'one', value: { kind: 'load_const', value: 1n } },
        { name: 'upd', value: { kind: 'update_prop', name: 'value', value: 'one' } },
      ],
      isPublic: true,
    }],
  };
}

describe('ANF interpreter — executeOnChainAuthoritative', () => {
  const sighash = deterministicSighash();
  const sighashHex = Utils.toHex(sighash);

  // Sign the sighash with the test private key. @bsv/sdk's `PrivateKey.sign`
  // takes the *message* and SHA-256 hashes it internally before signing,
  // matching how `LocalSigner.sign` produces a signature in the SDK
  // (it passes SHA256(preimage) as the message, so the actual digest signed
  // is SHA256(SHA256(preimage)) = the BIP-143 sighash). To produce a sig
  // that verifies against `sighash` directly, we'd have to hand the raw
  // sighash to @bsv/sdk's API. Looking at PublicKey.verify, it also
  // SHA-256s the message argument — so to verify against `sighash` we have
  // to feed `sighash` as the *raw bytes* and sign via the same path.
  //
  // Using PrivateKey.sign(msg) and PublicKey.verify(msg, sig) where
  // msg = sighash bytes gives a self-consistent round-trip: both sides
  // hash msg the same way before doing the actual ECDSA op. This is what
  // the real-crypto interpreter mode does.
  const priv = PrivateKey.fromHex(TEST_PRIV_HEX);
  const pubHex = priv.toPublicKey().toDER('hex') as string;
  const sigDerHex = priv.sign(sighash).toDER('hex') as string;

  // ECDSA — checkSig
  describe('checkSig', () => {
    const anf = makeP2PKHGuardANF();

    it('passes with a real signature against the supplied sighash', () => {
      const result = executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sig: sigDerHex, pk: pubHex },
        [],
        { sighash: sighashHex },
      );
      expect(result.state.value).toBe(1n);
    });

    it('throws AssertionFailureError when signature is corrupted', () => {
      // Flip the last byte of r — invalidates the signature.
      const broken = sigDerHex.slice(0, -2) + '00';
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sig: broken, pk: pubHex },
        [],
        { sighash: sighashHex },
      )).toThrow(AssertionFailureError);
    });

    it('throws AssertionFailureError when pubkey does not match the signing key', () => {
      const otherPub = PrivateKey.fromHex(
        '11'.repeat(32),
      ).toPublicKey().toDER('hex') as string;
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sig: sigDerHex, pk: otherPub },
        [],
        { sighash: sighashHex },
      )).toThrow(AssertionFailureError);
    });

    it('throws AssertionFailureError when sighash differs from the one signed', () => {
      const otherSighash = Hash.sha256(
        Utils.toArray('different-message', 'utf8'),
      );
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sig: sigDerHex, pk: pubHex },
        [],
        { sighash: otherSighash },
      )).toThrow(AssertionFailureError);
    });
  });

  // checkPreimage — verifies hash256(preimage) === sighash
  describe('checkPreimage', () => {
    const anf = makePreimageGuardANF();
    // Construct a preimage whose hash256 equals our sighash. To do this
    // backwards, we pick an arbitrary preimage and use its sighash.
    const preimageHex = 'deadbeefcafebabef00d1234567890abcdef1234';
    const preimageBytes = Utils.toArray(preimageHex, 'hex');
    const matchingSighash = Hash.hash256(preimageBytes);

    it('passes when hash256(preimage) === sighash', () => {
      const result = executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { preimage: preimageHex },
        [],
        { sighash: matchingSighash },
      );
      expect(result.state.value).toBe(1n);
    });

    it('throws AssertionFailureError when preimage hashes to a different sighash', () => {
      // Use the deterministic sighash above (which doesn't match this preimage).
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { preimage: preimageHex },
        [],
        { sighash: sighashHex },
      )).toThrow(AssertionFailureError);
    });

    it('throws AssertionFailureError when preimage is corrupted', () => {
      const corrupted = 'aa' + preimageHex.slice(2);
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { preimage: corrupted },
        [],
        { sighash: matchingSighash },
      )).toThrow(AssertionFailureError);
    });
  });

  // checkMultiSig — accepts iff all sigs verify against some prefix of pks.
  describe('checkMultiSig', () => {
    const anf = makeMultisigGuardANF();
    const priv2 = PrivateKey.fromHex('22'.repeat(32));
    const pub2 = priv2.toPublicKey().toDER('hex') as string;
    const sig2 = priv2.sign(sighash).toDER('hex') as string;

    it('passes when both sigs verify against a 2-of-2 pubkey set', () => {
      const result = executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sigs: [sigDerHex, sig2], pks: [pubHex, pub2] },
        [],
        { sighash: sighashHex },
      );
      expect(result.state.value).toBe(1n);
    });

    it('throws AssertionFailureError when one signature is corrupted', () => {
      const broken = sig2.slice(0, -2) + '00';
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sigs: [sigDerHex, broken], pks: [pubHex, pub2] },
        [],
        { sighash: sighashHex },
      )).toThrow(AssertionFailureError);
    });
  });

  // Mode parity: lenient + strict still mock crypto.
  describe('lenient + strict modes still mock crypto (no regression)', () => {
    const anf = makeP2PKHGuardANF();

    it('lenient computeNewState passes with garbage sig/pk', () => {
      const result = computeNewState(
        anf, 'unlock', { value: 0n }, { sig: 'deadbeef', pk: 'cafebabe' },
      );
      expect(result.value).toBe(1n);
    });

    it('strict executeStrict passes with garbage sig/pk', () => {
      const result = executeStrict(
        anf, 'unlock', { value: 0n }, { sig: 'deadbeef', pk: 'cafebabe' },
      );
      expect(result.state.value).toBe(1n);
    });
  });

  // Surface-area sanity.
  describe('error surface', () => {
    it('throws if the supplied sighash is not exactly 32 bytes', () => {
      const anf = makeP2PKHGuardANF();
      expect(() => executeOnChainAuthoritative(
        anf,
        'unlock',
        { value: 0n },
        { sig: sigDerHex, pk: pubHex },
        [],
        { sighash: 'aa'.repeat(20) },
      )).toThrow(/sighash must be exactly 32 bytes/);
    });

    it('exposes executeOnChainAuthoritative + OnChainCryptoContext from the package entry point', () => {
      expect(typeof RunarSdk.executeOnChainAuthoritative).toBe('function');
      expect(RunarSdk.executeOnChainAuthoritative).toBe(executeOnChainAuthoritative);
    });
  });
});
