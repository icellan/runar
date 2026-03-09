/**
 * SchnorrZKP integration test — stateless contract with EC scalar math verification.
 *
 * ## How It Works
 *
 * SchnorrZKP implements a non-interactive Schnorr zero-knowledge proof verifier
 * on-chain. The contract locks funds to an EC public key P, and spending requires
 * proving knowledge of the discrete logarithm k (i.e., P = k*G) without revealing k.
 *
 * ### Constructor
 *   - pubKey: Point — the EC public key (64-byte uncompressed x[32] || y[32])
 *
 * ### Method: verify(rPoint: Point, s: bigint)
 *   The prover generates a proof:
 *     1. Pick random nonce r, compute R = r*G (commitment)
 *     2. The contract derives the challenge e = bin2num(hash256(R || P)) (Fiat-Shamir)
 *     3. Prover computes s = r + e*k (mod n) (response)
 *   The contract checks: s*G === R + e*P (Schnorr verification equation)
 *
 *   The Fiat-Shamir transform makes the proof non-interactive and prevents the
 *   prover from choosing a favorable challenge.
 *
 * ### Script Size
 *   ~877 KB — dominated by EC scalar multiplication codegen (each ecMulGen call
 *   compiles to ~290 KB of Bitcoin Script doing 256 double-and-add iterations).
 *
 * ### Important Notes
 *   - No Sig param — this is a pure mathematical proof, not an ECDSA signature
 *   - All params (Point, bigint) are passed as explicit values to contract.call()
 *   - The contract is stateless (SmartContract base class)
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { ecMulGen, encodePoint, EC_N } from './helpers/crypto.js';
import { createHash } from 'crypto';
import { createProvider } from './helpers/node.js';

/**
 * Derive the Fiat-Shamir challenge e = bin2num(hash256(R || P)).
 * hash256 is double-SHA256, bin2num interprets LE signed-magnitude.
 */
function deriveChallenge(rPointHex: string, pubKeyHex: string): bigint {
  const combined = Buffer.from(rPointHex + pubKeyHex, 'hex');
  const hash1 = createHash('sha256').update(combined).digest();
  const hash2 = createHash('sha256').update(hash1).digest();
  // bin2num: little-endian signed-magnitude decode
  let result = 0n;
  const isNeg = (hash2[hash2.length - 1] & 0x80) !== 0;
  const lastByte = hash2[hash2.length - 1] & 0x7f;
  for (let i = hash2.length - 1; i >= 1; i--) {
    result = (result << 8n) | BigInt(i === hash2.length - 1 ? lastByte : hash2[i]);
  }
  result = (result << 8n) | BigInt(hash2[0]);
  return isNeg ? -result : result;
}

describe('SchnorrZKP', () => {
  it('should compile the contract', () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('SchnorrZKP');
    expect(artifact.script.length).toBeGreaterThan(0);
  });

  it('should produce a very large script (~877 KB)', () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');
    const scriptBytes = artifact.script.length / 2;
    // EC-heavy scripts are typically ~877 KB
    expect(scriptBytes).toBeGreaterThan(100000);
    expect(scriptBytes).toBeLessThan(2000000);
  });

  it('should deploy with an EC public key point', async () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // Generate a keypair: k is private, P = k*G is the public key point
    const k = 42n; // simple deterministic private key for testing
    const [px, py] = ecMulGen(k);

    // Constructor: (pubKey: Point) — 64-byte hex (x[32] || y[32])
    const pubKeyHex = encodePoint(px, py);
    const contract = new RunarContract(artifact, [pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 50000 });
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with a different public key', async () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // Different private key
    const k = 123456789n;
    const [px, py] = ecMulGen(k);
    const pubKeyHex = encodePoint(px, py);

    const contract = new RunarContract(artifact, [pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 50000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy and spend with a valid Schnorr ZKP proof', async () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // --- Step 1: Generate keypair ---
    // Private key k (the secret we're proving knowledge of)
    const k = 42n;
    // Public key P = k*G (deployed into the contract)
    const [px, py] = ecMulGen(k);
    const pubKeyHex = encodePoint(px, py);

    const contract = new RunarContract(artifact, [pubKeyHex]);
    await contract.deploy(provider, signer, { satoshis: 50000 });

    // --- Step 2: Generate the Schnorr ZKP proof ---
    // Pick a random nonce r (using a deterministic value for tests)
    const r = 7777n;
    // Compute the nonce commitment R = r*G
    const [rx, ry] = ecMulGen(r);
    const rPointHex = encodePoint(rx, ry);

    // Derive challenge e via Fiat-Shamir: e = bin2num(hash256(R || P))
    const e = deriveChallenge(rPointHex, pubKeyHex);

    // Response s = r + e*k (mod n)
    // This is the core of the Schnorr protocol: s encodes knowledge of k
    // without revealing it, because s*G = r*G + e*k*G = R + e*P
    const s = ((r + ((((e % EC_N) + EC_N) % EC_N) * k) % EC_N) % EC_N + EC_N) % EC_N;

    // --- Step 3: Call verify(rPoint, s) to spend the UTXO ---
    // The contract derives e internally and checks: s*G === R + e*P
    const { txid: spendTxid } = await contract.call(
      'verify',
      [rPointHex, s],
      provider,
      signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should reject spend with invalid s value', async () => {
    const artifact = compileContract('examples/ts/schnorr-zkp/SchnorrZKP.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // Generate keypair: k is private, P = k*G is the public key
    const k = 42n;
    const [px, py] = ecMulGen(k);
    const pubKeyHex = encodePoint(px, py);

    const contract = new RunarContract(artifact, [pubKeyHex]);
    await contract.deploy(provider, signer, { satoshis: 50000 });

    // Generate valid proof
    const r = 7777n;
    const [rx, ry] = ecMulGen(r);
    const rPointHex = encodePoint(rx, ry);
    const e = deriveChallenge(rPointHex, pubKeyHex);
    const s = ((r + ((((e % EC_N) + EC_N) % EC_N) * k) % EC_N) % EC_N + EC_N) % EC_N;

    // Tamper s by adding 1 mod n
    const tamperedS = (s + 1n) % EC_N;

    await expect(
      contract.call('verify', [rPointHex, tamperedS], provider, signer),
    ).rejects.toThrow();
  });
});
