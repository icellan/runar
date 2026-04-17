/**
 * P-384 (NIST P-384 / secp384r1) on-chain integration tests.
 *
 * These tests deploy minimal contracts that exercise verifyECDSA_P384 and the
 * P-384 curve built-ins on the BSV regtest node, confirming that the compiled
 * Bitcoin Script actually executes correctly and that the off-chain TypeScript
 * helpers produce values the on-chain verifier accepts.
 *
 * ## Test Contracts
 *
 * **P384Verify** — verifyECDSA_P384 with a known message hash baked into the
 * constructor. The locking script commits to (p384PubKeyHash, msgHash). Spending
 * supplies (p384Sig, p384PubKey) as method parameters.
 *
 * **P384OnCurveTest** — verifies the p384OnCurve built-in compiles and runs
 * on-chain. A 96-byte P-384 uncompressed point is baked into the constructor
 * and the spending method asserts the point is on the curve.
 *
 * **P384MulGenTest** — verifies p384MulGen + p384EncodeCompressed by computing
 * k*G off-chain and asserting the on-chain result matches.
 *
 * ## Signing Model
 *
 * `verifyECDSA_P384(msg, sig, pubKey)`:
 *   - msg: raw message bytes (SHA-256 hashed internally by the Script verifier;
 *     the codegen uses OP_SHA256 for both P-256 and P-384)
 *   - sig: 96-byte raw r||s (NOT DER-encoded, 48 bytes each)
 *   - pubKey: 49-byte compressed public key (02/03 prefix + 48-byte x-coord)
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { createHash, createECDH, createSign, generateKeyPairSync } from 'node:crypto';

// ---------------------------------------------------------------------------
// Off-chain P-384 helpers
// ---------------------------------------------------------------------------

/**
 * A P-384 key pair for use in integration tests.
 */
interface P384KeyPair {
  /** 96-byte uncompressed point (x[48] || y[48]), as hex — this is P384Point. */
  pointHex: string;
  /** 49-byte compressed public key (02/03 + x[48]), as hex. */
  pubKeyCompressedHex: string;
  /** 20-byte HASH160 of the compressed pubkey, as hex. */
  pubKeyHashHex: string;
  /** Sign a raw message; returns the 96-byte r||s signature as hex. */
  sign: (msg: Buffer) => string;
}

/**
 * Generate a fresh P-384 key pair using the Node.js built-in crypto module.
 *
 * The sign function SHA-256 hashes the message internally before signing —
 * this matches the on-chain verifyECDSA_P384 behaviour which also hashes the
 * raw msg argument before verification.
 */
function generateP384KeyPair(): P384KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });

  // Extract the 97-byte raw uncompressed public key from the SPKI DER encoding.
  // P-384 SPKI always ends with 04 || x[48] || y[48].
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const uncompressed = spkiDer.subarray(-97); // 04 || x[48] || y[48]
  const x = uncompressed.subarray(1, 49);
  const y = uncompressed.subarray(49, 97);

  // pointHex: 96-byte x||y (no prefix), matching the P384Point convention.
  const pointHex = uncompressed.subarray(1).toString('hex');

  // Compress: prefix byte 02 (even y) or 03 (odd y).
  const prefix = (y[y.length - 1]! & 1) === 0 ? 0x02 : 0x03;
  const compressed = Buffer.concat([Buffer.from([prefix]), x]);
  const pubKeyCompressedHex = compressed.toString('hex');

  // HASH160 = RIPEMD160(SHA256(compressed_pubkey)).
  const sha = createHash('sha256').update(compressed).digest();
  const pubKeyHashHex = createHash('ripemd160').update(sha).digest('hex');

  const sign = (msg: Buffer): string => {
    // createSign('SHA256') hashes the message with SHA-256 internally before
    // signing — this matches the on-chain verifier which also SHA-256 hashes
    // the raw msg argument.
    const signer = createSign('SHA256');
    signer.update(msg);
    const derSig = signer.sign(privateKey);

    // Parse DER: 30 <total-len> [81 <extended-len>] 02 <r-len> <r> 02 <s-len> <s>
    // P-384 signatures often exceed 127 bytes, using the long-form length (0x81).
    const der = Buffer.from(derSig);
    let pos = 0;
    if (der[pos++] !== 0x30) throw new Error('expected DER SEQUENCE');
    if (der[pos] === 0x81) pos += 2; else pos += 1;
    pos++; // skip 02 (r tag)
    const rLen = der[pos++]!;
    const rBytes = der.subarray(pos, pos + rLen);
    pos += rLen;
    pos++; // skip 02 (s tag)
    const sLen = der[pos++]!;
    const sBytes = der.subarray(pos, pos + sLen);

    // Right-align r and s into 48-byte buffers. DER may prepend a 0x00 sign
    // byte when the high bit is set, making the encoded length 49 — take the
    // low 48 bytes so the padding is dropped rather than truncating the value.
    const r = Buffer.alloc(48);
    const s = Buffer.alloc(48);
    const rSrc = rBytes.length > 48 ? rBytes.subarray(rBytes.length - 48) : rBytes;
    const sSrc = sBytes.length > 48 ? sBytes.subarray(sBytes.length - 48) : sBytes;
    rSrc.copy(r, 48 - rSrc.length);
    sSrc.copy(s, 48 - sSrc.length);

    return Buffer.concat([r, s]).toString('hex');
  };

  return { pointHex, pubKeyCompressedHex, pubKeyHashHex, sign };
}

/**
 * Compute the compressed encoding of k*G on P-384 using Node's ECDH API.
 *
 * ECDH treats the private key as the scalar, so ECDH.getPublicKey() = k*G.
 */
function computeP384KTimesGCompressed(k: bigint): string {
  const ecdh = createECDH('secp384r1');
  // Set the private key as a 48-byte big-endian buffer.
  const kBytes = Buffer.alloc(48);
  let remaining = k;
  for (let i = 47; i >= 0 && remaining > 0n; i--) {
    kBytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  ecdh.setPrivateKey(kBytes);
  // 'compressed' format returns the 49-byte encoding as hex.
  return ecdh.getPublicKey('hex', 'compressed');
}

// ---------------------------------------------------------------------------
// P384Verify: verifyECDSA_P384
// ---------------------------------------------------------------------------

const p384VerifySource = `
import { SmartContract, assert, hash160, verifyECDSA_P384 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P384Verify extends SmartContract {
  readonly p384PubKeyHash: ByteString;
  readonly msg: ByteString;

  constructor(p384PubKeyHash: ByteString, msg: ByteString) {
    super(p384PubKeyHash, msg);
    this.p384PubKeyHash = p384PubKeyHash;
    this.msg = msg;
  }

  public spend(p384Sig: ByteString, p384PubKey: ByteString) {
    assert(hash160(p384PubKey) == this.p384PubKeyHash);
    assert(verifyECDSA_P384(this.msg, p384Sig, p384PubKey));
  }
}
`;

describe('P-384 on-chain integration', () => {
  it('P384Verify: should compile, deploy, and spend with a valid P-384 signature', async () => {
    const artifact = compileSource(p384VerifySource, 'P384Verify.runar.ts');
    expect(artifact.contractName).toBe('P384Verify');

    // Fixed test message — raw bytes baked into the locking script.
    // verifyECDSA_P384 SHA-256 hashes the msg argument internally before
    // verification. createSign('SHA256') also hashes internally before signing.
    // Both sides operate on the same raw message — the on-chain verifier will
    // apply SHA-256 to derive the digest for verification.
    const testMsg = Buffer.from('runar p-384 integration test message');
    const testMsgHex = testMsg.toString('hex');

    // Generate a fresh P-384 keypair and sign the test message.
    const kp = generateP384KeyPair();
    const sigHex = kp.sign(testMsg);

    const contract = new RunarContract(artifact, [kp.pubKeyHashHex, testMsgHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call(
      'spend',
      [sigHex, kp.pubKeyCompressedHex],
      provider,
      signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('P384Verify: should reject a signature from a different keypair', async () => {
    const artifact = compileSource(p384VerifySource, 'P384Verify.runar.ts');

    const testMsg = Buffer.from('runar p-384 wrong-sig test');
    const testMsgHex = testMsg.toString('hex');

    // Commit to kp1's pubkey in the constructor…
    const kp1 = generateP384KeyPair();
    // …but sign with kp2 (different keypair). hash160 check passes (we still
    // present kp1's pubkey), but ECDSA verification will fail.
    const kp2 = generateP384KeyPair();
    const badSigHex = kp2.sign(testMsg);

    const contract = new RunarContract(artifact, [kp1.pubKeyHashHex, testMsgHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    await contract.deploy(provider, signer, { satoshis: 500_000 });

    // The call must fail because the signature does not verify against kp1's pubkey.
    await expect(
      contract.call('spend', [badSigHex, kp1.pubKeyCompressedHex], provider, signer),
    ).rejects.toThrow();
  });

  // ---------------------------------------------------------------------------
  // P384OnCurve: p384OnCurve built-in
  // ---------------------------------------------------------------------------

  it('P384OnCurve: should accept a valid P-384 point on-chain', async () => {
    const source = `
import { SmartContract, assert, p384OnCurve } from 'runar-lang';
import type { P384Point } from 'runar-lang';

class P384OnCurveTest extends SmartContract {
  readonly pt: P384Point;

  constructor(pt: P384Point) {
    super(pt);
    this.pt = pt;
  }

  public check() {
    assert(p384OnCurve(this.pt));
  }
}
`;
    const artifact = compileSource(source, 'P384OnCurveTest.runar.ts');
    expect(artifact.contractName).toBe('P384OnCurveTest');

    // Get a fresh valid P-384 point (96-byte x||y, no prefix).
    const kp = generateP384KeyPair();
    const ptHex = kp.pointHex; // x[48] || y[48], big-endian

    const contract = new RunarContract(artifact, [ptHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call('check', [], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  // ---------------------------------------------------------------------------
  // P384MulGen: p384MulGen + p384EncodeCompressed
  // ---------------------------------------------------------------------------

  it('P384MulGen: should verify k*G on-chain via p384MulGen and p384EncodeCompressed', async () => {
    const source = `
import { SmartContract, assert, p384MulGen, p384EncodeCompressed } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P384MulGenTest extends SmartContract {
  readonly expectedCompressed: ByteString;

  constructor(expectedCompressed: ByteString) {
    super(expectedCompressed);
    this.expectedCompressed = expectedCompressed;
  }

  public check(k: bigint) {
    assert(p384EncodeCompressed(p384MulGen(k)) == this.expectedCompressed);
  }
}
`;
    const artifact = compileSource(source, 'P384MulGenTest.runar.ts');
    expect(artifact.contractName).toBe('P384MulGenTest');

    // Compute 7*G off-chain to get the expected compressed point.
    const k = 7n;
    const expectedCompressedHex = computeP384KTimesGCompressed(k);

    const contract = new RunarContract(artifact, [expectedCompressedHex]);

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 500_000 });
    expect(deployTxid).toBeTruthy();

    const { txid: spendTxid } = await contract.call('check', [k], provider, signer);
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });
});
