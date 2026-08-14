import { createHash, createSign, generateKeyPairSync } from 'node:crypto';
import type { KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrivateKey } from '@bsv/sdk';
import { describe, expect, it } from 'vitest';
import { compile } from 'runar-compiler';
import {
  ALICE,
  BOB,
  ScriptExecutionContract,
  signTestMessage,
  TestContract,
} from 'runar-testing';

const __dirname = dirname(fileURLToPath(import.meta.url));
const source = readFileSync(join(__dirname, 'R1K1Wallet.runar.ts'), 'utf8');

function hash160(hex: string): string {
  const sha = createHash('sha256').update(Buffer.from(hex, 'hex')).digest();
  return createHash('ripemd160').update(sha).digest('hex');
}

function compressP256PublicKey(publicKey: KeyObject): string {
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const point = spki.subarray(spki.length - 65);
  const x = point.subarray(1, 33);
  const y = point.subarray(33, 65);
  const prefix = (y[31]! & 1) === 0 ? '02' : '03';
  return prefix + x.toString('hex');
}

function derToRawP256(der: Buffer): string {
  let offset = 2;
  if (der[0] !== 0x30) throw new Error('P-256 signature is not a DER sequence');

  if (der[offset++] !== 0x02) throw new Error('P-256 signature has no r value');
  const rLength = der[offset++]!;
  const r = der.subarray(offset, offset + rLength);
  offset += rLength;

  if (der[offset++] !== 0x02) throw new Error('P-256 signature has no s value');
  const sLength = der[offset++]!;
  const s = der.subarray(offset, offset + sLength);

  const raw = Buffer.alloc(64);
  r.subarray(Math.max(0, r.length - 32)).copy(raw, Math.max(0, 32 - r.length));
  s.subarray(Math.max(0, s.length - 32)).copy(raw, Math.max(32, 64 - s.length));
  return raw.toString('hex');
}

function signPreimage(preimageHex: string): string {
  const firstHash = createHash('sha256')
    .update(Buffer.from(preimageHex, 'hex'))
    .digest();
  const signer = createSign('SHA256');
  signer.update(firstHash);
  return derToRawP256(signer.sign(r1PrivateKey) as Buffer);
}

const {
  privateKey: r1PrivateKey,
  publicKey: r1PublicKey,
} = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const R1_PUBKEY = compressP256PublicKey(r1PublicKey);
const R1_SALT = 'a5'.repeat(32);
const R1_SALTED_PUBKEY_HASH = hash160(R1_PUBKEY + R1_SALT);
const PREIMAGE = '00'.repeat(120) + '41000000';
const R1_SIG = signPreimage(PREIMAGE);
const K1_SIG = signTestMessage(ALICE.privKey);

function wallet() {
  return TestContract.fromSource(source, {
    r1SaltedPubKeyHash: R1_SALTED_PUBKEY_HASH,
    k1PubKeyHash: ALICE.pubKeyHash,
  });
}

describe('R1K1Wallet', () => {
  it('accepts the R1 path for the committed P-256 public key', () => {
    const result = wallet().call('spendR1', {
      r1Sig: R1_SIG,
      r1PubKey: R1_PUBKEY,
      r1Salt: R1_SALT,
      txPreimage: PREIMAGE,
    });
    expect(result.success).toBe(true);
  });

  it('rejects the R1 path under an uncommitted P-256 public key', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const result = wallet().call('spendR1', {
      r1Sig: R1_SIG,
      r1PubKey: compressP256PublicKey(publicKey),
      r1Salt: R1_SALT,
      txPreimage: PREIMAGE,
    });
    expect(result.success).toBe(false);
  });

  it('rejects the same R1 key when its private salt does not match the commitment', () => {
    const mismatchedSalt = '5a'.repeat(32);
    const result = wallet().call('spendR1', {
      r1Sig: R1_SIG,
      r1PubKey: R1_PUBKEY,
      r1Salt: mismatchedSalt,
      txPreimage: PREIMAGE,
    });
    expect(result.success).toBe(false);
  });

  it('produces different commitments for the same R1 key under unique salts', () => {
    const otherSalt = '3c'.repeat(32);
    expect(hash160(R1_PUBKEY + otherSalt)).not.toBe(R1_SALTED_PUBKEY_HASH);
  });

  it('rejects an R1 signature bound to a different preimage', () => {
    const result = wallet().call('spendR1', {
      r1Sig: R1_SIG,
      r1PubKey: R1_PUBKEY,
      r1Salt: R1_SALT,
      txPreimage: '01' + PREIMAGE.slice(2),
    });
    expect(result.success).toBe(false);
  });

  it('accepts the K1 recovery path for the committed recovery key', () => {
    const result = wallet().call('recoverK1', {
      k1Sig: K1_SIG,
      k1PubKey: ALICE.pubKey,
    });
    expect(result.success).toBe(true);
  });

  it('executes the compiled K1 recovery branch with a real transaction signature', () => {
    const compiled = ScriptExecutionContract.fromSource(
      source,
      {
        r1SaltedPubKeyHash: R1_SALTED_PUBKEY_HASH,
        k1PubKeyHash: ALICE.pubKeyHash,
      },
      'R1K1Wallet.runar.ts',
    );
    const result = compiled.executeSigned(
      'recoverK1',
      ['', ALICE.pubKey],
      0,
      PrivateKey.fromHex(ALICE.privKey),
    );
    expect(result.success, result.error).toBe(true);
  });

  it('rejects the K1 recovery path under an uncommitted key', () => {
    const result = wallet().call('recoverK1', {
      k1Sig: signTestMessage(BOB.privKey),
      k1PubKey: BOB.pubKey,
    });
    expect(result.success).toBe(false);
  });

  it('compiles both transaction-bound R1 and independent K1 paths', () => {
    const result = compile(source, { fileName: 'R1K1Wallet.runar.ts' });
    expect(result.success).toBe(true);
    expect(result.artifact).toBeDefined();

    const anf = JSON.stringify(result.anf, (_key, value) =>
      typeof value === 'bigint' ? value.toString() : value,
    );
    expect(anf).toContain('spendR1');
    expect(anf).toContain('recoverK1');
    expect(anf).toContain('check_preimage');
    expect(anf).toContain('extractSigHashType');
    expect(anf).toContain('verifyECDSA_P256');
    expect(anf).toContain('cat');
    expect(anf).toContain('checkSig');
  });
});
