import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, wotsKeygen, wotsSign } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'PostQuantumWallet.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hash160(data: Uint8Array): Uint8Array {
  const sha = createHash('sha256').update(data).digest();
  return createHash('ripemd160').update(sha).digest();
}

// ECDSA mock key
const ecdsaPubKey = new Uint8Array(33);
ecdsaPubKey[0] = 0x02;
ecdsaPubKey[1] = 0xAB;
const ecdsaPubKeyHash = hash160(ecdsaPubKey);

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

    // Mock ECDSA signature (checkSig is mocked to true in interpreter)
    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;

    // WOTS-sign the ECDSA signature bytes (ECDSA sig IS the WOTS message)
    const wotsSig = wotsSign(ecdsaSig, sk, pubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered WOTS+ signature', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;
    const wotsSig = wotsSign(ecdsaSig, sk, pubSeed);

    // Tamper with WOTS signature
    const tampered = new Uint8Array(wotsSig);
    tampered[100] ^= 0xff;

    const result = contract.call('spend', {
      wotsSig: toHex(tampered),
      wotsPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
      pubKey: toHex(ecdsaPubKey),
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

    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;
    const wotsSig = wotsSign(ecdsaSig, sk, pubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
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
    const wrongWotsSig = wotsSign(new Uint8Array(72), wrongKP.sk, wrongPubSeed);

    const result = contract.call('spend', {
      wotsSig: toHex(wrongWotsSig),
      wotsPubKey: toHex(wrongKP.pk),
      sig: toHex(new Uint8Array(72)),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects WOTS+ signed over wrong ECDSA sig', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      wotsPubKeyHash: toHex(wotsPubKeyHash),
    });

    // Sign one ECDSA sig with WOTS, but provide a different ECDSA sig to the contract
    const ecdsaSig1 = new Uint8Array(72);
    ecdsaSig1[0] = 0x30;
    const wotsSig = wotsSign(ecdsaSig1, sk, pubSeed);

    const ecdsaSig2 = new Uint8Array(72);
    ecdsaSig2[0] = 0x30;
    ecdsaSig2[1] = 0xFF; // different sig

    const result = contract.call('spend', {
      wotsSig: toHex(wotsSig),
      wotsPubKey: toHex(pk),
      sig: toHex(ecdsaSig2),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(false);
  });
});
