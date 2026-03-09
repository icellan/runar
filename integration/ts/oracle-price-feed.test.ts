/**
 * OraclePriceFeed integration test — stateless contract with Rabin signature verification.
 *
 * ## How It Works
 *
 * OraclePriceFeed locks funds to an oracle's Rabin public key and a receiver's ECDSA
 * public key. To spend, the oracle must sign a price that exceeds a hardcoded threshold
 * (50,000), AND the receiver must provide their ECDSA signature. This demonstrates a
 * two-party spending condition: oracle data feed + receiver authorization.
 *
 * ### Constructor
 *   - oraclePubKey: RabinPubKey (bigint) — the Rabin modulus n = p*q
 *   - receiver: PubKey — the ECDSA public key authorized to receive funds
 *
 * ### Method: settle(price: bigint, rabinSig: RabinSig, padding: ByteString, sig: Sig)
 *   1. Encode price as 8-byte little-endian (num2bin)
 *   2. Verify Rabin signature: (sig² + padding) mod n === SHA-256(encoded_price) mod n
 *   3. Assert price > 50000
 *   4. Verify receiver's ECDSA signature (checkSig)
 *
 * ### How Rabin Signatures Work
 *   - Key: two large primes p, q where p ≡ q ≡ 3 (mod 4), public key n = p*q
 *   - Sign: find square root of H(msg) mod n using CRT (needs p, q)
 *   - Verify: check sig² ≡ H(msg) + padding (mod n) — very cheap on-chain (just OP_MUL + OP_MOD)
 *   - Padding: tries values 0..255 until H(msg) + padding is a quadratic residue mod both p and q
 *
 * ### Important Notes
 *   - The Sig param (ECDSA) is auto-computed by the SDK when passed as null
 *   - The Rabin signature, padding, and price must be computed in the test
 *   - Uses small test primes (7879, 7883) — real deployments need 1024+ bit primes
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { generateRabinKeyPair, rabinSign } from './helpers/crypto.js';
import { createHash } from 'crypto';
import { createProvider } from './helpers/node.js';

/**
 * Encode a number as little-endian bytes (num2bin format).
 * This matches the encoding the contract uses internally for Rabin message hashing.
 */
function num2binLE(value: bigint, length: number): Buffer {
  const buf = Buffer.alloc(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

describe('OraclePriceFeed', () => {
  it('should compile the contract', () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('OraclePriceFeed');
    expect(artifact.script.length).toBeGreaterThan(0);
  });

  it('should deploy with Rabin oracle key and receiver pubkey', async () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // Generate Rabin keypair for the oracle
    const rabinKP = generateRabinKeyPair();

    // Create a receiver wallet for the ECDSA pubkey
    const receiver = createWallet();

    // Constructor: (oraclePubKey: RabinPubKey, receiver: PubKey)
    // RabinPubKey is bigint (n = p*q), PubKey is hex string
    const contract = new RunarContract(artifact, [rabinKP.n, receiver.pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with a different oracle key', async () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');

    const provider = createProvider();
    const { signer } = await createFundedWallet(provider);

    // Use the same deterministic keypair but different receiver
    const rabinKP = generateRabinKeyPair();
    const receiver = createWallet();

    const contract = new RunarContract(artifact, [rabinKP.n, receiver.pubKeyHex]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy and spend with a valid oracle price above threshold', async () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');

    const provider = createProvider();

    // --- Step 1: Create the oracle's Rabin keypair ---
    // In production, the oracle would have a large (1024+ bit) Rabin key.
    // For testing we use small primes that are both ≡ 3 (mod 4).
    const rabinKP = generateRabinKeyPair();

    // --- Step 2: Create the receiver (who will also be the signer) ---
    // The receiver's ECDSA key must match the pubkey in the constructor.
    const receiverWallet = await createFundedWallet(provider);

    // Constructor: (oraclePubKey, receiver)
    const contract = new RunarContract(artifact, [
      rabinKP.n,
      receiverWallet.pubKeyHex,
    ]);
    await contract.deploy(provider, receiverWallet.signer, {});

    // --- Step 3: Oracle signs a price above the 50,000 threshold ---
    const price = 55001n;
    // Encode price as 8-byte LE — matches the contract's num2bin(price, 8)
    const msgBytes = num2binLE(price, 8);
    const { sig: rabinSig, padding } = rabinSign(msgBytes, rabinKP);

    // --- Step 4: Call settle(price, rabinSig, padding, sig) ---
    // - price: the oracle-attested value (must be > 50000)
    // - rabinSig: square root of H(msg)+padding mod n
    // - padding: offset to make hash a quadratic residue
    // - sig: null → SDK auto-computes ECDSA signature from the receiver's key
    const { txid: spendTxid } = await contract.call(
      'settle',
      [price, rabinSig, padding, null],
      provider,
      receiverWallet.signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should reject settle with price below threshold', async () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');

    const provider = createProvider();
    const rabinKP = generateRabinKeyPair();

    // Receiver is the funded signer
    const receiverWallet = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      rabinKP.n,
      receiverWallet.pubKeyHex,
    ]);
    await contract.deploy(provider, receiverWallet.signer, {});

    // Oracle signs a price BELOW the 50,000 threshold
    const price = 49999n;
    const msgBytes = num2binLE(price, 8);
    const { sig: rabinSig, padding } = rabinSign(msgBytes, rabinKP);

    // settle(price, rabinSig, padding, sig) — Rabin sig is valid but price < 50000
    await expect(
      contract.call(
        'settle',
        [price, rabinSig, padding, null],
        provider,
        receiverWallet.signer,
      ),
    ).rejects.toThrow();
  });

  it('should reject settle with wrong receiver signature', async () => {
    const artifact = compileContract('examples/ts/oracle-price/OraclePriceFeed.runar.ts');

    const provider = createProvider();
    const rabinKP = generateRabinKeyPair();

    // Deploy with receiver=walletA
    const walletA = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      rabinKP.n,
      walletA.pubKeyHex,
    ]);
    await contract.deploy(provider, walletA.signer, {});

    // Oracle signs a valid price above threshold
    const price = 55001n;
    const msgBytes = num2binLE(price, 8);
    const { sig: rabinSig, padding } = rabinSign(msgBytes, rabinKP);

    // Call settle with walletB — ECDSA checkSig will fail
    const walletB = await createFundedWallet(provider);

    await expect(
      contract.call(
        'settle',
        [price, rabinSig, padding, null],
        provider,
        walletB.signer,
      ),
    ).rejects.toThrow();
  });
});
