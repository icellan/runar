import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, slhKeygen, slhSign, SLH_SHA2_128s } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'SPHINCSWallet.runar.ts'), 'utf8');

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

// SLH-DSA keypair
const params = SLH_SHA2_128s;
const slhSeed = new Uint8Array(3 * params.n);
slhSeed[0] = 0x42;
const { sk, pk } = slhKeygen(params, slhSeed);
const slhdsaPubKeyHash = hash160(pk);

describe('SPHINCSWallet (Hybrid ECDSA + SLH-DSA-SHA2-128s)', () => {
  it('accepts a valid hybrid spend', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Mock ECDSA signature (checkSig is mocked to true in interpreter)
    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;

    // SLH-DSA-sign the ECDSA signature bytes
    const slhdsaSig = slhSign(params, ecdsaSig, sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered SLH-DSA signature', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;
    const slhdsaSig = slhSign(params, ecdsaSig, sk);

    // Tamper with SLH-DSA signature
    const tampered = new Uint8Array(slhdsaSig);
    tampered[params.n + 10] ^= 0xff;

    const result = contract.call('spend', {
      slhdsaSig: toHex(tampered),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong ECDSA public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Different ECDSA pubkey whose hash160 won't match
    const wrongEcdsaPubKey = new Uint8Array(33);
    wrongEcdsaPubKey[0] = 0x03;
    wrongEcdsaPubKey.fill(0xFF, 1);

    const ecdsaSig = new Uint8Array(72);
    ecdsaSig[0] = 0x30;
    const slhdsaSig = slhSign(params, ecdsaSig, sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig),
      pubKey: toHex(wrongEcdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong SLH-DSA public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Different SLH-DSA keypair whose hash160 won't match
    const wrongSeed = new Uint8Array(3 * params.n);
    wrongSeed.fill(0xFF);
    const wrongKP = slhKeygen(params, wrongSeed);
    const wrongSlhdsaSig = slhSign(params, new Uint8Array(72), wrongKP.sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(wrongSlhdsaSig),
      slhdsaPubKey: toHex(wrongKP.pk),
      sig: toHex(new Uint8Array(72)),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects SLH-DSA signed over wrong ECDSA sig', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Sign one ECDSA sig with SLH-DSA, but provide a different ECDSA sig
    const ecdsaSig1 = new Uint8Array(72);
    ecdsaSig1[0] = 0x30;
    const slhdsaSig = slhSign(params, ecdsaSig1, sk);

    const ecdsaSig2 = new Uint8Array(72);
    ecdsaSig2[0] = 0x30;
    ecdsaSig2[1] = 0xFF;

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig2),
      pubKey: toHex(ecdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('accepts multiple spends from same SLH-DSA keypair (stateless)', () => {
    const ecdsaSig1 = new Uint8Array(72);
    ecdsaSig1[0] = 0x30;
    ecdsaSig1[1] = 0x01;
    const slhdsaSig1 = slhSign(params, ecdsaSig1, sk);

    const contract1 = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });
    expect(contract1.call('spend', {
      slhdsaSig: toHex(slhdsaSig1),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig1),
      pubKey: toHex(ecdsaPubKey),
    }).success).toBe(true);

    const ecdsaSig2 = new Uint8Array(72);
    ecdsaSig2[0] = 0x30;
    ecdsaSig2[1] = 0x02;
    const slhdsaSig2 = slhSign(params, ecdsaSig2, sk);

    const contract2 = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });
    expect(contract2.call('spend', {
      slhdsaSig: toHex(slhdsaSig2),
      slhdsaPubKey: toHex(pk),
      sig: toHex(ecdsaSig2),
      pubKey: toHex(ecdsaPubKey),
    }).success).toBe(true);
  });
});
