import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { TestContract, ALICE, signTestMessage } from 'runar-testing';
import { compile } from 'runar-compiler';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'P384Wallet.runar.sol'), 'utf8');
const FILE_NAME = 'P384Wallet.runar.sol';

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

/** Generate a P-384 key pair using Node.js crypto (secp384r1 = P-384). */
function p384Keygen() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: 'secp384r1',
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const spki = publicKey as unknown as Buffer;
  const rawPub = spki.subarray(spki.length - 97); // uncompressed: 04 || x[48] || y[48]
  const x = rawPub.subarray(1, 49);
  const y = rawPub.subarray(49, 97);
  const prefix = (y[y.length - 1]! & 1) === 0 ? 0x02 : 0x03;
  const pkCompressed = new Uint8Array(49);
  pkCompressed[0] = prefix;
  pkCompressed.set(x, 1);
  return { privateKey: privateKey as unknown as Buffer, pkCompressed };
}

/** Sign msg with P-384. Returns 96-byte raw r||s signature. */
function p384Sign(msg: Uint8Array, privateKey: Buffer): Uint8Array {
  const { createSign } = require('node:crypto');
  const signer = createSign('SHA256');
  signer.update(msg);
  const derSig = signer.sign({ key: privateKey, format: 'der', type: 'pkcs8', dsaEncoding: 'der' });
  // P-384 DER SEQUENCE may use long-form length (0x81 <len>)
  let offset = 0;
  if (derSig[offset++] !== 0x30) throw new Error('expected DER SEQUENCE');
  if (derSig[offset] === 0x81) offset += 2; else offset += 1;
  offset++; // skip 02
  const rLen = derSig[offset++]!;
  const r = derSig.subarray(offset, offset + rLen);
  offset += rLen;
  offset++; // skip 02
  const sLen = derSig[offset++]!;
  const s = derSig.subarray(offset, offset + sLen);
  const raw = new Uint8Array(96);
  raw.set(r.length > 48 ? r.subarray(r.length - 48) : r, 48 - Math.min(r.length, 48));
  raw.set(s.length > 48 ? s.subarray(s.length - 48) : s, 96 - Math.min(s.length, 48));
  return raw;
}

// secp256k1 ECDSA key (Alice)
const ecdsaPubKeyHex = ALICE.pubKey;
const ecdsaPubKey = hexToU8(ecdsaPubKeyHex);
const ecdsaPubKeyHash = hash160(ecdsaPubKey);
const ecdsaSigHex = signTestMessage(ALICE.privKey);
const ecdsaSigBytes = hexToU8(ecdsaSigHex);

// P-384 key pair
const { privateKey: p384PrivKey, pkCompressed: p384PubKey } = p384Keygen();
const p384PubKeyHash = hash160(p384PubKey);

describe('P384Wallet (Solidity, Hybrid secp256k1 + P-384)', () => {
  it('accepts a valid hybrid spend', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p384PubKeyHash: toHex(p384PubKeyHash),
    }, FILE_NAME);

    const p384Sig = p384Sign(ecdsaSigBytes, p384PrivKey);

    const result = contract.call('spend', {
      p384Sig: toHex(p384Sig),
      p384PubKey: toHex(p384PubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(true);
  });

  it('rejects wrong secp256k1 public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p384PubKeyHash: toHex(p384PubKeyHash),
    }, FILE_NAME);

    const wrongEcdsaPubKey = new Uint8Array(33);
    wrongEcdsaPubKey[0] = 0x03;
    wrongEcdsaPubKey.fill(0xFF, 1);

    const p384Sig = p384Sign(ecdsaSigBytes, p384PrivKey);

    const result = contract.call('spend', {
      p384Sig: toHex(p384Sig),
      p384PubKey: toHex(p384PubKey),
      sig: ecdsaSigHex,
      pubKey: toHex(wrongEcdsaPubKey),
    });
    expect(result.success).toBe(false);
  });

  it('rejects wrong P-384 public key hash', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p384PubKeyHash: toHex(p384PubKeyHash),
    }, FILE_NAME);

    const { privateKey: wrongPrivKey, pkCompressed: wrongPubKey } = p384Keygen();
    const wrongP384Sig = p384Sign(ecdsaSigBytes, wrongPrivKey);

    const result = contract.call('spend', {
      p384Sig: toHex(wrongP384Sig),
      p384PubKey: toHex(wrongPubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });

  it('rejects a tampered P-384 signature (signed over wrong bytes)', () => {
    const contract = TestContract.fromSource(source, {
      ecdsaPubKeyHash: toHex(ecdsaPubKeyHash),
      p384PubKeyHash: toHex(p384PubKeyHash),
    }, FILE_NAME);

    const wrongMsg = new Uint8Array(ecdsaSigBytes.length);
    wrongMsg[0] = 0x30;
    wrongMsg[1] = 0xff;
    const tamperedP384Sig = p384Sign(wrongMsg, p384PrivKey);

    const result = contract.call('spend', {
      p384Sig: toHex(tamperedP384Sig),
      p384PubKey: toHex(p384PubKey),
      sig: ecdsaSigHex,
      pubKey: ecdsaPubKeyHex,
    });
    expect(result.success).toBe(false);
  });
});

describe('P384Wallet (Solidity) — compile check', () => {
  it('compiles successfully to Bitcoin Script', () => {
    const result = compile(source, { fileName: FILE_NAME });
    if (!result.success) {
      console.error('P384Wallet (Sol) compile errors:', result.diagnostics);
    }
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();
    expect(result.artifact!.script.length).toBeGreaterThan(0);
  });
});
