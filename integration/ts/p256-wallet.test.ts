/**
 * P-256 (NIST P-256 / secp256r1) on-chain integration tests.
 *
 * These tests deploy minimal contracts that exercise verifyECDSA_P256 and the
 * P-256 curve built-ins on the BSV regtest node, confirming that the compiled
 * Bitcoin Script actually executes correctly and that the off-chain TypeScript
 * helpers produce values the on-chain verifier accepts.
 *
 * ## Test Contracts
 *
 * **P256Verify** — verifyECDSA_P256 with a known message hash baked into the
 * constructor. The locking script commits to (p256PubKeyHash, msgHash). Spending
 * supplies (p256Sig, p256PubKey) as method parameters.
 *
 * **P256OnCurveTest** — verifies the p256OnCurve built-in compiles and runs
 * on-chain. A 64-byte P-256 uncompressed point is baked into the constructor
 * and the spending method asserts the point is on the curve.
 *
 * **P256MulGenTest** — verifies p256MulGen + p256EncodeCompressed by computing
 * k*G off-chain and asserting the on-chain result matches.
 *
 * ## Signing Model
 *
 * `verifyECDSA_P256(msg, sig, pubKey)`:
 *   - msg: raw message bytes (SHA-256 hashed internally by the Script verifier)
 *   - sig: 64-byte raw r||s (NOT DER-encoded)
 *   - pubKey: 33-byte compressed public key (02/03 prefix + 32-byte x-coord)
 */

import { describe, it, expect } from 'vitest';
import { compileSource } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';
import { createHash, createECDH, createSign, generateKeyPairSync } from 'node:crypto';

// ---------------------------------------------------------------------------
// Off-chain P-256 helpers
// ---------------------------------------------------------------------------

/**
 * A P-256 key pair for use in integration tests.
 */
interface P256KeyPair {
  /** 64-byte uncompressed point (x[32] || y[32]), as hex — this is P256Point. */
  pointHex: string;
  /** 33-byte compressed public key (02/03 + x), as hex. */
  pubKeyCompressedHex: string;
  /** 20-byte HASH160 of the compressed pubkey, as hex. */
  pubKeyHashHex: string;
  /** Sign a raw message; returns the 64-byte r||s signature as hex. */
  sign: (msg: Buffer) => string;
}

/**
 * Generate a fresh P-256 key pair using the Node.js built-in crypto module.
 *
 * The sign function SHA-256 hashes the message internally before signing —
 * this matches the on-chain verifyECDSA_P256 behaviour which also hashes the
 * raw msg argument before verification.
 */
function generateP256KeyPair(): P256KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  // Extract the 65-byte raw uncompressed public key from the SPKI DER encoding.
  // P-256 SPKI always ends with 04 || x[32] || y[32].
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const uncompressed = spkiDer.subarray(-65); // 04 || x[32] || y[32]
  const x = uncompressed.subarray(1, 33);
  const y = uncompressed.subarray(33, 65);

  // pointHex: 64-byte x||y (no prefix), matching the P256Point convention.
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

    // Parse DER: 30 <total-len> 02 <r-len> <r> 02 <s-len> <s>
    const der = Buffer.from(derSig);
    let pos = 2; // skip 30 <total-len>
    pos++; // skip 02 (r tag)
    const rLen = der[pos++]!;
    const rBytes = der.subarray(pos, pos + rLen);
    pos += rLen;
    pos++; // skip 02 (s tag)
    const sLen = der[pos++]!;
    const sBytes = der.subarray(pos, pos + sLen);

    // Right-align r and s into 32-byte buffers. DER may prepend a 0x00 sign
    // byte when the high bit is set, making the encoded length 33 — take the
    // low 32 bytes so the padding is dropped rather than truncating the value.
    const r = Buffer.alloc(32);
    const s = Buffer.alloc(32);
    const rSrc = rBytes.length > 32 ? rBytes.subarray(rBytes.length - 32) : rBytes;
    const sSrc = sBytes.length > 32 ? sBytes.subarray(sBytes.length - 32) : sBytes;
    rSrc.copy(r, 32 - rSrc.length);
    sSrc.copy(s, 32 - sSrc.length);

    return Buffer.concat([r, s]).toString('hex');
  };

  return { pointHex, pubKeyCompressedHex, pubKeyHashHex, sign };
}

/**
 * Compute the compressed encoding of k*G on P-256 using Node's ECDH API.
 *
 * ECDH treats the private key as the scalar, so ECDH.getPublicKey() = k*G.
 */
function computeP256KTimesGCompressed(k: bigint): string {
  const ecdh = createECDH('prime256v1');
  // Set the private key as a 32-byte big-endian buffer.
  const kBytes = Buffer.alloc(32);
  let remaining = k;
  for (let i = 31; i >= 0 && remaining > 0n; i--) {
    kBytes[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  ecdh.setPrivateKey(kBytes);
  // 'compressed' format returns the 33-byte encoding as hex.
  return ecdh.getPublicKey('hex', 'compressed');
}

// ---------------------------------------------------------------------------
// P256Verify: verifyECDSA_P256
// ---------------------------------------------------------------------------

const p256VerifySource = `
import { SmartContract, assert, hash160, verifyECDSA_P256 } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P256Verify extends SmartContract {
  readonly p256PubKeyHash: ByteString;
  readonly msg: ByteString;

  constructor(p256PubKeyHash: ByteString, msg: ByteString) {
    super(p256PubKeyHash, msg);
    this.p256PubKeyHash = p256PubKeyHash;
    this.msg = msg;
  }

  public spend(p256Sig: ByteString, p256PubKey: ByteString) {
    assert(hash160(p256PubKey) == this.p256PubKeyHash);
    assert(verifyECDSA_P256(this.msg, p256Sig, p256PubKey));
  }
}
`;

describe('P-256 on-chain integration', () => {
  it('P256Verify: should compile, deploy, and spend with a valid P-256 signature', async () => {
    const artifact = compileSource(p256VerifySource, 'P256Verify.runar.ts');
    expect(artifact.contractName).toBe('P256Verify');

    // Fixed test message — raw bytes baked into the locking script.
    // verifyECDSA_P256 SHA-256 hashes the msg argument internally before
    // verification. createSign('SHA256') also hashes internally before signing.
    // Both sides operate on the same raw message — the on-chain verifier will
    // apply SHA-256 to derive the digest for verification.
    const testMsg = Buffer.from('runar p-256 integration test message');
    const testMsgHex = testMsg.toString('hex');

    // Generate a fresh P-256 keypair and sign the test message.
    const kp = generateP256KeyPair();
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

  it('P256Verify: should reject a signature from a different keypair', async () => {
    const artifact = compileSource(p256VerifySource, 'P256Verify.runar.ts');

    const testMsg = Buffer.from('runar p-256 wrong-sig test');
    const testMsgHex = testMsg.toString('hex');

    // Commit to kp1's pubkey in the constructor…
    const kp1 = generateP256KeyPair();
    // …but sign with kp2 (different keypair). hash160 check passes (we still
    // present kp1's pubkey), but ECDSA verification will fail.
    const kp2 = generateP256KeyPair();
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
  // P256OnCurve: p256OnCurve built-in
  // ---------------------------------------------------------------------------

  it('P256OnCurve: should accept a valid P-256 point on-chain', async () => {
    const source = `
import { SmartContract, assert, p256OnCurve } from 'runar-lang';
import type { P256Point } from 'runar-lang';

class P256OnCurveTest extends SmartContract {
  readonly pt: P256Point;

  constructor(pt: P256Point) {
    super(pt);
    this.pt = pt;
  }

  public check() {
    assert(p256OnCurve(this.pt));
  }
}
`;
    const artifact = compileSource(source, 'P256OnCurveTest.runar.ts');
    expect(artifact.contractName).toBe('P256OnCurveTest');

    // Get a fresh valid P-256 point (64-byte x||y, no prefix).
    const kp = generateP256KeyPair();
    const ptHex = kp.pointHex; // x[32] || y[32], big-endian

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
  // P256MulGen: p256MulGen + p256EncodeCompressed
  // ---------------------------------------------------------------------------

  it('P256MulGen: should verify k*G on-chain via p256MulGen and p256EncodeCompressed', async () => {
    const source = `
import { SmartContract, assert, p256MulGen, p256EncodeCompressed } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P256MulGenTest extends SmartContract {
  readonly expectedCompressed: ByteString;

  constructor(expectedCompressed: ByteString) {
    super(expectedCompressed);
    this.expectedCompressed = expectedCompressed;
  }

  public check(k: bigint) {
    assert(p256EncodeCompressed(p256MulGen(k)) == this.expectedCompressed);
  }
}
`;
    const artifact = compileSource(source, 'P256MulGenTest.runar.ts');
    expect(artifact.contractName).toBe('P256MulGenTest');

    // Compute 7*G off-chain to get the expected compressed point.
    const k = 7n;
    const expectedCompressedHex = computeP256KTimesGCompressed(k);

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
