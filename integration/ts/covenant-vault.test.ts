/**
 * CovenantVault integration test — stateless contract with checkSig + checkPreimage.
 *
 * ## How It Works
 *
 * CovenantVault demonstrates a covenant pattern: it constrains HOW funds can be spent,
 * not just WHO can spend them. The contract checks:
 *   1. The owner's ECDSA signature (authentication via checkSig)
 *   2. The transaction preimage (via checkPreimage, which enables script-level
 *      inspection of the spending transaction)
 *   3. That the spending amount >= minAmount (covenant rule)
 *
 * ### What is checkPreimage / OP_PUSH_TX?
 *   checkPreimage verifies a BIP-143 sighash preimage against the spending transaction.
 *   This is implemented via the OP_PUSH_TX technique: the unlocking script pushes
 *   both a preimage (the raw BIP-143 serialization) and an ECDSA signature computed
 *   with private key k=1 (whose public key is the generator point G). The locking
 *   script verifies this signature against the preimage, which proves the preimage
 *   is genuine. Once verified, the script can inspect transaction fields (outputs,
 *   amounts, etc.) by parsing the preimage — enabling covenant rules.
 *
 * ### Constructor
 *   - owner: PubKey — the ECDSA public key that must sign to spend
 *   - recipient: Addr — the hash160 of the authorized recipient's public key
 *   - minAmount: bigint — minimum satoshis that must be sent to the recipient
 *
 * ### Method: spend(sig: Sig, amount: bigint, txPreimage: SigHashPreimage)
 *   The compiler inserts an implicit _opPushTxSig parameter before the declared params.
 *   The full unlocking script order is: <opPushTxSig> <sig> <amount> <txPreimage>
 *
 *   - sig: owner's ECDSA signature (auto-computed by SDK when null)
 *   - amount: satoshis to send to recipient (must be >= minAmount)
 *   - txPreimage: BIP-143 sighash preimage (auto-computed by SDK when null)
 *
 * ### SDK Auto-Compute
 *   The SDK's call() method detects SigHashPreimage params set to null and
 *   automatically computes the OP_PUSH_TX signature and BIP-143 preimage.
 *   It also auto-computes Sig params set to null using the signer's private key.
 *   This means the caller only needs to provide the amount — both cryptographic
 *   values are computed from the spending transaction.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract, RPCProvider } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';

function createProvider() {
  return new RPCProvider('http://localhost:18332', 'regtest', 'regtest', {
    autoMine: true,
    network: 'testnet',
  });
}

describe('CovenantVault', () => {
  it('should compile the CovenantVault contract', () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');
    expect(artifact).toBeTruthy();
    expect(artifact.contractName).toBe('CovenantVault');
  });

  it('should deploy with owner, recipient, and minAmount', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const recipient = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      recipient.pubKeyHash,
      1000n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
    expect(typeof deployTxid).toBe('string');
    expect(deployTxid.length).toBe(64);
  });

  it('should deploy with zero minAmount', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const recipient = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      recipient.pubKeyHash,
      0n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy with large minAmount', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const owner = createWallet();
    const recipient = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      owner.pubKeyHex,
      recipient.pubKeyHash,
      100_000_000n, // 1 BTC in satoshis
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  it('should deploy with same key as owner and recipient', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const ownerAndRecipient = createWallet();
    const { signer } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      ownerAndRecipient.pubKeyHex,
      ownerAndRecipient.pubKeyHash,
      500n,
    ]);

    const { txid: deployTxid } = await contract.deploy(provider, signer, {});
    expect(deployTxid).toBeTruthy();
  });

  /**
   * Deploy and spend with valid owner signature, preimage, and amount >= minAmount.
   *
   * Steps:
   *   1. Create owner wallet (will be the signer — their ECDSA key must match the constructor)
   *   2. Deploy with (ownerPubKey, recipientPubKeyHash, minAmount=1000)
   *   3. Call spend(null, 2000n, null):
   *      - null Sig → SDK auto-computes ECDSA signature from signer's private key
   *      - 2000n   → amount (>= minAmount of 1000)
   *      - null SigHashPreimage → SDK auto-computes BIP-143 preimage and _opPushTxSig
   *   4. The SDK builds the unlocking script: <opPushTxSig> <sig> <amount> <txPreimage>
   *   5. On-chain, the script verifies checkSig(sig, owner), checkPreimage(txPreimage),
   *      and asserts amount >= minAmount
   */
  it('should spend with valid signature and amount >= minAmount', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const recipient = createWallet();

    // Owner must be the signer — their ECDSA key must match constructor's owner param
    const { signer: ownerSigner, pubKeyHex: ownerPubKeyHex, pubKeyHash: recipientPKH } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      ownerPubKeyHex,
      recipient.pubKeyHash,
      1000n, // minAmount
    ]);

    await contract.deploy(provider, ownerSigner, {});

    // spend(sig=null, amount=2000, txPreimage=null)
    // SDK auto-computes both Sig and SigHashPreimage from the spending transaction
    const { txid: spendTxid } = await contract.call(
      'spend',
      [null, 2000n, null],
      provider,
      ownerSigner,
    );
    expect(spendTxid).toBeTruthy();
    expect(typeof spendTxid).toBe('string');
    expect(spendTxid.length).toBe(64);
  });

  it('should reject spend with amount below minAmount', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const recipient = createWallet();

    // Owner must be the signer
    const { signer: ownerSigner, pubKeyHex: ownerPubKeyHex } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      ownerPubKeyHex,
      recipient.pubKeyHash,
      1000n, // minAmount=1000
    ]);

    await contract.deploy(provider, ownerSigner, {});

    // spend(sig=null, amount=500, txPreimage=null) — amount < minAmount should fail
    await expect(
      contract.call('spend', [null, 500n, null], provider, ownerSigner),
    ).rejects.toThrow();
  });
});
