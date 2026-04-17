/**
 * Ordinal NFT integration test — 1sat ordinals inscription on P2PKH.
 *
 * Deploys a P2PKH contract with an image inscription at exactly 1 satoshi,
 * verifies the inscription is on-chain, reconnects via fromTxId and confirms
 * the inscription round-trips, then spends the UTXO (transfer).
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract } from 'runar-sdk';
import {
  buildInscriptionEnvelope,
  parseInscriptionEnvelope,
} from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('Ordinal NFT (1sat inscription)', () => {
  it('should deploy a P2PKH contract with a text inscription at 1 sat', async () => {
    const artifact = compileContract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);

    // Attach a text inscription
    const textHex = Buffer.from('Hello, 1sat ordinals!').toString('hex');
    contract.withInscription({ contentType: 'text/plain', data: textHex });

    // Deploy at exactly 1 satoshi
    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();
    expect(txid.length).toBe(64);

    // Verify the on-chain script contains the inscription envelope
    const tx = await provider.getTransaction(txid);
    const lockingScript = tx.outputs[0]!.script;
    expect(lockingScript).toContain('0063036f726451'); // OP_FALSE OP_IF PUSH3 "ord" OP_1
    expect(lockingScript).toContain(textHex);
  });

  it('should round-trip inscription via fromTxId', async () => {
    const artifact = compileContract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const imageData = 'ff'.repeat(64); // fake 64-byte "image"
    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription({ contentType: 'image/png', data: imageData });

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });

    // Reconnect from chain
    const reconnected = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('image/png');
    expect(reconnected.inscription!.data).toBe(imageData);

    // Locking scripts should match
    expect(reconnected.getLockingScript()).toBe(contract.getLockingScript());
  });

  it('should spend (transfer) an inscribed ordinal NFT', async () => {
    const artifact = compileContract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const textHex = Buffer.from('Transferable NFT').toString('hex');
    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription({ contentType: 'text/plain', data: textHex });

    await contract.deploy(provider, signer, { satoshis: 1 });

    // Spend: unlock(sig, pubKey) — null args are auto-computed
    const { txid: spendTxid } = await contract.call(
      'unlock', [null, null], provider, signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should deploy with a large inscription (OP_PUSHDATA2)', async () => {
    const artifact = compileContract('examples/ts/ordinal-nft/OrdinalNFT.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // 500 bytes — forces OP_PUSHDATA2 encoding
    const largeData = 'ab'.repeat(500);
    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription({ contentType: 'image/jpeg', data: largeData });

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();

    // Reconnect and verify
    const reconnected = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('image/jpeg');
    expect(reconnected.inscription!.data).toBe(largeData);
  });
});
