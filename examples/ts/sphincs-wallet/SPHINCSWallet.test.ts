import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { TestContract, slhKeygen, slhSign, SLH_SHA2_128s, ALICE, BOB, signTestMessage } from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'SPHINCSWallet.runar.ts'), 'utf8');

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToU8(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function hash160(data: Uint8Array): Uint8Array {
  const sha = createHash('sha256').update(data).digest();
  return createHash('ripemd160').update(sha).digest();
}

// Real ECDSA key (ALICE from runar-testing test keys)
const ecdsaPubKeyHex = ALICE.pubKey;
const ecdsaPubKeyHashHex = ALICE.pubKeyHash;
const ecdsaSigHex = signTestMessage(ALICE.privKey);

// SLH-DSA keypair
const params = SLH_SHA2_128s;
const slhSeed = new Uint8Array(3 * params.n);
slhSeed[0] = 0x42;
const { sk, pk } = slhKeygen(params, slhSeed);
const slhdsaPubKeyHash = hash160(pk);

describe('SPHINCSWallet (Hybrid ECDSA + SLH-DSA-SHA2-128s)', () => {
  it('accepts a valid hybrid spend', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Real ECDSA signature (signTestMessage uses deterministic RFC 6979)
    const ecdsaSigBytes = hexToU8(ecdsaSigHex);

    // SLH-DSA-sign the ECDSA signature bytes
    const slhdsaSig = slhSign(params, ecdsaSigBytes, sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(true);
  });

  it('rejects a tampered SLH-DSA signature', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    const ecdsaSigBytes = hexToU8(ecdsaSigHex);
    const slhdsaSig = slhSign(params, ecdsaSigBytes, sk);

    // Tamper with SLH-DSA signature
    const tampered = new Uint8Array(slhdsaSig);
    tampered[params.n + 10] ^= 0xff;

    const result = contract.call('spend', {
      slhdsaSig: toHex(tampered),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong ECDSA public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // BOB's pubkey whose hash160 won't match ALICE's ecdsaPubKeyHash
    const wrongEcdsaPubKeyHex = BOB.pubKey;

    const ecdsaSigBytes = hexToU8(ecdsaSigHex);
    const slhdsaSig = slhSign(params, ecdsaSigBytes, sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: wrongEcdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong SLH-DSA public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Different SLH-DSA keypair whose hash160 won't match
    const wrongSeed = new Uint8Array(3 * params.n);
    wrongSeed.fill(0xFF);
    const wrongKP = slhKeygen(params, wrongSeed);
    const ecdsaSigBytes = hexToU8(ecdsaSigHex);
    const wrongSlhdsaSig = slhSign(params, ecdsaSigBytes, wrongKP.sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(wrongSlhdsaSig),
      slhdsaPubKey: toHex(wrongKP.pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects SLH-DSA signed over wrong ECDSA sig', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });

    // Sign one set of bytes with SLH-DSA, but provide the real ECDSA sig
    const fakeBytes = new Uint8Array(72);
    fakeBytes[0] = 0x30;
    const slhdsaSig = slhSign(params, fakeBytes, sk);

    const result = contract.call('spend', {
      slhdsaSig: toHex(slhdsaSig),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('accepts multiple spends from same SLH-DSA keypair (stateless)', () => {
    // Both spends use the same real ECDSA sig (deterministic) so SLH-DSA signs the same bytes
    const ecdsaSigBytes = hexToU8(ecdsaSigHex);
    const slhdsaSig1 = slhSign(params, ecdsaSigBytes, sk);

    const contract1 = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });
    expect(contract1.call('spend', {
      slhdsaSig: toHex(slhdsaSig1),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    }).success).toBe(true);

    const slhdsaSig2 = slhSign(params, ecdsaSigBytes, sk);

    const contract2 = TestContract.fromSource(source, {
      ecdsaPubKeyHash: ecdsaPubKeyHashHex,
      slhdsaPubKeyHash: toHex(slhdsaPubKeyHash),
    });
    expect(contract2.call('spend', {
      slhdsaSig: toHex(slhdsaSig2),
      slhdsaPubKey: toHex(pk),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    }).success).toBe(true);
  });
});
