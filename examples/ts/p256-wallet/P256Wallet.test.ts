import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';
import { compile } from 'runar-compiler';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P256Wallet.runar.ts'), 'utf8');

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

/** Generate a P-256 key pair using Node.js crypto (prime256v1 = P-256). */
function p256Keygen() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // Extract compressed public key from SPKI DER:
  // SPKI for P-256 ends with 65 bytes (04 || x[32] || y[32]) — compress it.
  const spki = publicKey as unknown as Buffer;
  const rawPub = spki.subarray(spki.length - 65); // uncompressed point
  const x = rawPub.subarray(1, 33);
  const y = rawPub.subarray(33, 65);
  const prefix = (y[y.length - 1]! & 1) === 0 ? 0x02 : 0x03;
  const pkCompressed = new Uint8Array(33);
  pkCompressed[0] = prefix;
  pkCompressed.set(x, 1);
  return { privateKey: privateKey as unknown as Buffer, pkCompressed };
}

/** Sign msg with P-256. Returns 64-byte raw r||s signature. */
function p256Sign(msg: Uint8Array, privateKey: Buffer): Uint8Array {
  const { createSign } = require('node:crypto');
  const signer = createSign('SHA256');
  signer.update(msg);
  // Node returns DER-encoded signature, we need raw r||s (64 bytes)
  const derSig = signer.sign({ key: privateKey, format: 'der', type: 'pkcs8', dsaEncoding: 'der' });
  // Parse DER: 30 len 02 rlen r 02 slen s
  let offset = 2; // skip 30 len
  offset++; // skip 02
  const rLen = derSig[offset++]!;
  const r = derSig.subarray(offset, offset + rLen);
  offset += rLen;
  offset++; // skip 02
  const sLen = derSig[offset++]!;
  const s = derSig.subarray(offset, offset + sLen);
  // Zero-pad r and s to 32 bytes each
  const raw = new Uint8Array(64);
  raw.set(r.length > 32 ? r.subarray(r.length - 32) : r, 32 - Math.min(r.length, 32));
  raw.set(s.length > 32 ? s.subarray(s.length - 32) : s, 64 - Math.min(s.length, 32));
  return raw;
}

// secp256k1 ECDSA key (Alice)
const ecdsaPubKeyHex = ALICE.pubKey;
const ecdsaPubKey = hexToU8(ecdsaPubKeyHex);
const ecdsaPubKeyHash = hash160(ecdsaPubKey);
const ecdsaSigHex = signTestMessage(ALICE.privKey);
const ecdsaSigBytes = hexToU8(ecdsaSigHex);

// P-256 key pair
const { privateKey: p256PrivKey, pkCompressed: p256PubKey } = p256Keygen();
const p256PubKeyHash = hash160(p256PubKey);

describe('P256Wallet (Hybrid secp256k1 + P-256)', () => {
  it('accepts a valid hybrid spend', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p256PubKeyHash: toHex(p256PubKeyHash),
    });

    // P-256-sign the secp256k1 sig bytes (secp256k1 sig IS the P-256 message)
    const p256Sig = p256Sign(ecdsaSigBytes, p256PrivKey);

    const result = contract.call('spend', {
      p256Sig: toHex(p256Sig),
      p256PubKey: toHex(p256PubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(true);
  });

  it('rejects wrong secp256k1 public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p256PubKeyHash: toHex(p256PubKeyHash),
    });

    // Different secp256k1 pubkey whose hash160 won't match
    const wrongEcdsaPubKey = new Uint8Array(33);
    wrongEcdsaPubKey[0] = 0x03;
    wrongEcdsaPubKey.fill(0xFF, 1);

    const p256Sig = p256Sign(ecdsaSigBytes, p256PrivKey);

    const result = contract.call('spend', {
      p256Sig: toHex(p256Sig),
      p256PubKey: toHex(p256PubKey),
      sig: ecdsaSigHex,
      pubKey: toHex(wrongEcdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong P-256 public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p256PubKeyHash: toHex(p256PubKeyHash),
    });

    // Different P-256 keypair whose hash160 won't match
    const { privateKey: wrongPrivKey, pkCompressed: wrongPubKey } = p256Keygen();
    const wrongP256Sig = p256Sign(ecdsaSigBytes, wrongPrivKey);

    const result = contract.call('spend', {
      p256Sig: toHex(wrongP256Sig),
      p256PubKey: toHex(wrongPubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a tampered P-256 signature (signed over wrong bytes)', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p256PubKeyHash: toHex(p256PubKeyHash),
    });

    // Sign different bytes with P-256 (not the secp256k1 sig), then present
    // the correct secp256k1 sig to the contract — P-256 verification must fail.
    const wrongMsg = new Uint8Array(ecdsaSigBytes.length);
    wrongMsg[0] = 0x30;
    wrongMsg[1] = 0xff; // differs from the real secp256k1 sig
    const tamperedP256Sig = p256Sign(wrongMsg, p256PrivKey);

    const result = contract.call('spend', {
      p256Sig: toHex(tamperedP256Sig),
      p256PubKey: toHex(p256PubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });
});

describe('P256Wallet — compile check', () => {
  it('compiles successfully to Bitcoin Script', () => {
    const result = compile(source, { fileName: 'P256Wallet.runar.ts' });
    if (!result.success) {
      console.error('P256Wallet compile errors:', result.diagnostics);
    }
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(0);
  });
});
