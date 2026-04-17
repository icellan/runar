/**
 * BSV-21 token integration test — ID-based fungible token inscriptions.
 *
 * BSV-21 (v2) tokens use deploy+mint as a single operation. The token ID
 * is the txid_vout of the inscription output. Unlike BSV-20 (tick-based),
 * BSV-21 allows admin-controlled distribution.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract, BSV21, parseInscriptionEnvelope } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('BSV-21 Token (1sat inscription)', () => {
  it('should deploy+mint a BSV-21 token', async () => {
    const artifact = compileContract('examples/ts/bsv21-token/BSV21Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV21.deployMint({
      amt: '1000000',
      dec: '18',
      sym: 'RNR',
    }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();

    // Verify on-chain script contains BSV-21 deploy+mint JSON
    const tx = await provider.getTransaction(txid);
    const script = tx.outputs[0]!.script;
    const inscription = parseInscriptionEnvelope(script);
    expect(inscription).not.toBeNull();
    expect(inscription!.contentType).toBe('application/bsv-20');

    const json = JSON.parse(
      Buffer.from(inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.p).toBe('bsv-20');
    expect(json.op).toBe('deploy+mint');
    expect(json.amt).toBe('1000000');
    expect(json.dec).toBe('18');
    expect(json.sym).toBe('RNR');

    // Token ID would be txid_0 (first output)
    const tokenId = `${txid}_0`;
    expect(tokenId).toMatch(/^[0-9a-f]{64}_0$/);
  });

  it('should create a BSV-21 transfer inscription', async () => {
    const artifact = compileContract('examples/ts/bsv21-token/BSV21Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    // First deploy+mint to get a token ID
    const deployContract = new RunarContract(artifact, [pubKeyHash]);
    deployContract.withInscription(BSV21.deployMint({ amt: '500', sym: 'TST' }));
    const { txid: deployTxid } = await deployContract.deploy(provider, signer, { satoshis: 1 });
    const tokenId = `${deployTxid}_0`;

    // Create a transfer inscription referencing that token ID
    const transferContract = new RunarContract(artifact, [pubKeyHash]);
    transferContract.withInscription(BSV21.transfer({ id: tokenId, amt: '100' }));
    const { txid: transferTxid } = await transferContract.deploy(provider, signer, { satoshis: 1 });
    expect(transferTxid).toBeTruthy();

    // Verify transfer JSON on-chain
    const tx = await provider.getTransaction(transferTxid);
    const inscription = parseInscriptionEnvelope(tx.outputs[0]!.script);
    expect(inscription).not.toBeNull();
    const json = JSON.parse(
      Buffer.from(inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.op).toBe('transfer');
    expect(json.id).toBe(tokenId);
    expect(json.amt).toBe('100');
  });

  it('should spend a BSV-21 transfer UTXO', async () => {
    const artifact = compileContract('examples/ts/bsv21-token/BSV21Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV21.transfer({
      id: '0000000000000000000000000000000000000000000000000000000000000001_0',
      amt: '50',
    }));

    await contract.deploy(provider, signer, { satoshis: 1 });

    // Spend via P2PKH unlock
    const { txid: spendTxid } = await contract.call(
      'unlock', [null, null], provider, signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should round-trip BSV-21 inscription via fromTxId', async () => {
    const artifact = compileContract('examples/ts/bsv21-token/BSV21Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV21.deployMint({
      amt: '999',
      dec: '2',
      sym: 'ABC',
      icon: 'https://example.com/icon.png',
    }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });

    const reconnected = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('application/bsv-20');

    const json = JSON.parse(
      Buffer.from(reconnected.inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.op).toBe('deploy+mint');
    expect(json.sym).toBe('ABC');
    expect(json.icon).toBe('https://example.com/icon.png');

    expect(reconnected.getLockingScript()).toBe(contract.getLockingScript());
  });
});
