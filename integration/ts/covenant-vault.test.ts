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
 *   3. That the transaction outputs match the expected P2PKH script to the recipient
 *      with amount >= minAmount (enforced by comparing hash256(expectedOutput) against
 *      extractOutputHash(txPreimage))
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
 * ### Method: spend(sig: Sig, txPreimage: SigHashPreimage)
 *   The compiler inserts an implicit _opPushTxSig parameter before the declared params.
 *   The full unlocking script order is: <opPushTxSig> <sig> <txPreimage>
 *
 *   The contract constructs the expected P2PKH output on-chain using the recipient
 *   address and minAmount from its constructor parameters, then verifies it matches
 *   the actual transaction outputs via hash256(expectedOutput) == extractOutputHash.
 *
 * ### Spending Limitation
 *   Covenant spending requires constructing a transaction whose outputs exactly match
 *   what the contract expects (a P2PKH output to the recipient for minAmount satoshis).
 *   The SDK's generic call() creates default outputs that don't match. For real
 *   applications, developers would construct the spending transaction manually or use
 *   the SDK's raw transaction builder. The covenant logic is fully verified by the TS
 *   unit tests and conformance golden files.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import { createFundedWallet, createWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

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

  // NOTE: Covenant spending (spend() method) requires constructing a transaction
  // whose outputs exactly match the expected P2PKH output enforced by the contract:
  //   output = num2bin(minAmount, 8) || "1976a914" || recipient || "88ac"
  // The SDK's generic call() creates default outputs that don't satisfy this
  // covenant constraint. In production, developers use the SDK's raw transaction
  // builder to construct the exact required output. The covenant verification
  // logic is fully covered by the TS unit tests and conformance golden files.

  it('should reject spend with wrong signer (checkSig fails before covenant check)', async () => {
    const artifact = compileContract('examples/ts/covenant-vault/CovenantVault.runar.ts');

    const provider = createProvider();
    const recipient = createWallet();

    // Deploy with owner=walletA
    const { signer: ownerSigner, pubKeyHex: ownerPubKeyHex } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [
      ownerPubKeyHex,
      recipient.pubKeyHash,
      1000n,
    ]);

    await contract.deploy(provider, ownerSigner, {});

    // Call spend with walletB — checkSig will fail on-chain
    const { signer: wrongSigner } = await createFundedWallet(provider);

    await expect(
      contract.call('spend', [null, null], provider, wrongSigner),
    ).rejects.toThrow();
  });
});
