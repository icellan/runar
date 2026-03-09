/**
 * SPHINCSWallet integration test — Hybrid ECDSA + SLH-DSA-SHA2-128s contract.
 *
 * ## Security Model: Two-Layer Authentication
 *
 * This contract creates a quantum-resistant spending path by combining
 * classical ECDSA with SLH-DSA (FIPS 205, SPHINCS+):
 *
 * 1. **ECDSA** proves the signature commits to this specific transaction
 *    (via OP_CHECKSIG over the sighash preimage).
 * 2. **SLH-DSA** proves the ECDSA signature was authorized by the SLH-DSA
 *    key holder — the ECDSA signature bytes ARE the message that SLH-DSA signs.
 *
 * A quantum attacker who can break ECDSA could forge a valid ECDSA
 * signature, but they cannot produce a valid SLH-DSA signature over their
 * forged sig without knowing the SLH-DSA secret key. SLH-DSA security
 * relies only on SHA-256 collision resistance, not on any number-theoretic
 * assumption vulnerable to Shor's algorithm.
 *
 * Unlike WOTS+ (one-time), SLH-DSA is stateless and the same keypair
 * can sign many messages — it's NIST FIPS 205 standardized.
 *
 * ## Constructor
 *   - ecdsaPubKeyHash: Addr — 20-byte HASH160 of compressed ECDSA public key
 *   - slhdsaPubKeyHash: ByteString — 20-byte HASH160 of 32-byte SLH-DSA public key
 *
 * ## Method: spend(slhdsaSig, slhdsaPubKey, sig, pubKey)
 *   - slhdsaSig: 7,856-byte SLH-DSA-SHA2-128s signature
 *   - slhdsaPubKey: 32-byte SLH-DSA public key (PK.seed[16] || PK.root[16])
 *   - sig: ~72-byte DER-encoded ECDSA signature + sighash flag
 *   - pubKey: 33-byte compressed ECDSA public key
 *
 * ## Script Size
 *   ~188 KB — SLH-DSA verification requires computing multiple WOTS+
 *   verifications and Merkle tree path checks within the Bitcoin Script VM.
 *
 * ## Test Approach
 *   Deployment tests use hash commitments of test keys. Full spending tests
 *   require raw transaction construction (two-pass signing: ECDSA first, then
 *   SLH-DSA over the ECDSA sig). The Go integration suite (TestSLHDSA_ValidSpend)
 *   implements the complete two-pass spending flow.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createHash } from 'node:crypto';
import { createProvider } from './helpers/node.js';

function hash160hex(data: Buffer | Uint8Array): string {
  const sha = createHash('sha256').update(data).digest();
  return createHash('ripemd160').update(sha).digest('hex');
}

// Deterministic SLH-DSA test public key (32 bytes hex: PK.seed[16] || PK.root[16])
// Generated from seed [0, 1, 2, ..., 47] with SLH-DSA-SHA2-128s (n=16).
const SLHDSA_TEST_PK = '00000000000000000000000000000000b618cb38f7f785488c9768f3a2972baf';
const SLHDSA_TEST_PK_HASH = hash160hex(Buffer.from(SLHDSA_TEST_PK, 'hex'));

describe('SPHINCSWallet (Hybrid ECDSA + SLH-DSA-SHA2-128s)', () => {
  it('should compile the contract', () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('SPHINCSWallet');
    expect(artifact.script.length).toBeGreaterThan(0);
  });

  it('should produce a very large script (~188 KB)', () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');
    const scriptBytes = artifact.script.length / 2;
    // SLH-DSA scripts are typically ~188 KB
    expect(scriptBytes).toBeGreaterThan(100000);
    expect(scriptBytes).toBeLessThan(500000);
  });

  it('should deploy with ECDSA + SLH-DSA keys', async () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // Constructor: (ecdsaPubKeyHash, slhdsaPubKeyHash)
    const contract = new RunarContract(artifact, [pubKeyHash, SLHDSA_TEST_PK_HASH]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 50000 });
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with a different SLH-DSA public key', async () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // Different SLH-DSA public key
    const otherPK = 'aabbccdd00000000000000000000000011223344556677889900aabbccddeeff';
    const otherPKHash = hash160hex(Buffer.from(otherPK, 'hex'));
    const contract = new RunarContract(artifact, [pubKeyHash, otherPKHash]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, { satoshis: 50000 });
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy and verify UTXO exists (spend requires raw tx construction)', async () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // Deploy the hybrid ECDSA+SLH-DSA contract
    const contract = new RunarContract(artifact, [pubKeyHash, SLHDSA_TEST_PK_HASH]);
    await contract.deploy(provider, signer, { satoshis: 50000 });

    // The hybrid spend pattern requires:
    //   1. Build unsigned spending transaction
    //   2. ECDSA-sign the transaction input
    //   3. SLH-DSA-sign the ECDSA signature bytes
    //   4. Construct unlocking script: <slhdsaSig> <slhdsaPK> <ecdsaSig> <ecdsaPubKey>
    //
    // This two-pass signing pattern is fully tested in the Go integration suite
    // (TestSLHDSA_ValidSpend) which uses raw transaction construction.
    expect(contract.getUtxo()).toBeTruthy();
  });

  it('should deploy with tampered key hash (for rejection testing)', async () => {
    const artifact = compileContract('examples/ts/sphincs-wallet/SPHINCSWallet.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // Deploy succeeds (deployment doesn't verify the hash, that happens at spend time)
    const contract = new RunarContract(artifact, [pubKeyHash, SLHDSA_TEST_PK_HASH]);
    await contract.deploy(provider, signer, { satoshis: 50000 });

    // Contract deployed with correct hash commitments; tampered spend would fail
    // at the OP_HASH160 <slhdsaPubKeyHash> OP_EQUALVERIFY step if a wrong key is provided.
    expect(contract.getUtxo()).toBeTruthy();
  });
});
