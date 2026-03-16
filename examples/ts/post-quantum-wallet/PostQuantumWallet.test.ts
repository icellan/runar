import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, wotsKeygen, wotsSign, ALICE, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumWallet.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToU8(hex: string): Uint8Array {
  const buf = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) buf[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return buf;
}

function hash160(data: Uint8Array): Uint8Array {
  const sha = createHash('sha256').update(data).digest();
  return createHash('ripemd160').update(sha).digest();
}

// Real ECDSA key from ALICE test key
const ecdsaPubKeyHex = ALICE.pubKey;
const ecdsaPubKey = hexToU8(ecdsaPubKeyHex);
const ecdsaPubKeyHash = hash160(ecdsaPubKey);
const ecdsaSigHex = signTestMessage(ALICE.privKey);
const ecdsaSigBytes = hexToU8(ecdsaSigHex);

// WOTS+ keypair
const seed = new Uint8Array(32);
seed[0] = 0x42;
const pubSeed = new Uint8Array(32);
pubSeed[0] = 0x01;
const { sk, pk } = wotsKeygen(seed, pubSeed);
const wotsPubKeyHash = hash160(pk);

describe('PostQuantumWallet (Hybrid ECDSA + WOTS+)', () => {
  it('accepts a valid hybrid spend', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    // WOTS-sign the real ECDSA signature bytes (ECDSA sig IS the WOTS message)
    const wotsSig = wotsSign(ecdsaSigBytes, sk, pubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered WOTS+ signature', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    const wotsSig = wotsSign(ecdsaSigBytes, sk, pubSeed);

    // Tamper with WOTS signature
    const tampered = new Uint8Array(wotsSig);
    tampered[100]! ^= 0xff;

    const result = contract.call('spend', {
      wotsSig: toHex(tampered),
      wotsPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong ECDSA public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    // Different ECDSA pubkey whose hash160 won't match
    const wrongEcdsaPubKey = new Uint8Array(33);
    wrongEcdsaPubKey[0] = 0x03;
    wrongEcdsaPubKey.fill(0xFF, 1);

    const wotsSig = wotsSign(ecdsaSigBytes, sk, pubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: toHex(wrongEcdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong WOTS+ public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    // Different WOTS keypair whose hash160 won't match
    const wrongSeed = new Uint8Array(32);
    wrongSeed[0] = 0x99;
    const wrongPubSeed = new Uint8Array(32);
    wrongPubSeed[0] = 0x77;
    const wrongKP = wotsKeygen(wrongSeed, wrongPubSeed);
    const wrongWotsSig = wotsSign(ecdsaSigBytes, wrongKP.sk, wrongPubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wrongWotsSig),
      wotsPubKey: toHex(wrongKP.pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects WOTS+ signed over wrong ECDSA sig', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    // Sign a dummy message with WOTS, but provide the real ECDSA sig to the contract
    const dummyMsg = new Uint8Array(ecdsaSigBytes.length);
    dummyMsg[0] = 0x30;
    dummyMsg[1] = 0xFF; // different from real ECDSA sig
    const wotsSig = wotsSign(dummyMsg, sk, pubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });
});
