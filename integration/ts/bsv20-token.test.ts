/**
 * BSV-20 token integration test — fungible token inscriptions on P2PKH.
 *
 * Demonstrates the full BSV-20 lifecycle: deploy a token, mint tokens,
 * and create a transfer inscription. Each is a separate 1-sat UTXO with
 * a P2PKH locking script and BSV-20 JSON inscription.
 */

import { describe, it, expect } from 'vitest';
import { compileContract } from './helpers/compile.js';
import { RunarContract, BSV20, parseInscriptionEnvelope } from 'runar-sdk';
import { createFundedWallet } from './helpers/wallet.js';
import { createProvider } from './helpers/node.js';

describe('BSV-20 Token (1sat inscription)', () => {
  it('should deploy a BSV-20 token', async () => {
    const artifact = compileContract('examples/ts/bsv20-token/BSV20Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV20.deploy({
      tick: 'RUNAR',
      max: '21000000',
      lim: '1000',
    }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();

    // Verify on-chain script contains BSV-20 deploy JSON
    const tx = await provider.getTransaction(txid);
    const script = tx.outputs[0]!.script;
    const inscription = parseInscriptionEnvelope(script);
    expect(inscription).not.toBeNull();
    expect(inscription!.contentType).toBe('application/bsv-20');

    const json = JSON.parse(
      Buffer.from(inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.p).toBe('bsv-20');
    expect(json.op).toBe('deploy');
    expect(json.tick).toBe('RUNAR');
    expect(json.max).toBe('21000000');
  });

  it('should mint BSV-20 tokens', async () => {
    const artifact = compileContract('examples/ts/bsv20-token/BSV20Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV20.mint({ tick: 'RUNAR', amt: '1000' }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();

    // Verify mint JSON on-chain
    const tx = await provider.getTransaction(txid);
    const inscription = parseInscriptionEnvelope(tx.outputs[0]!.script);
    expect(inscription).not.toBeNull();
    const json = JSON.parse(
      Buffer.from(inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.op).toBe('mint');
    expect(json.amt).toBe('1000');
  });

  it('should create a BSV-20 transfer inscription and spend it', async () => {
    const artifact = compileContract('examples/ts/bsv20-token/BSV20Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV20.transfer({ tick: 'RUNAR', amt: '50' }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });
    expect(txid).toBeTruthy();

    // Verify transfer JSON on-chain
    const tx = await provider.getTransaction(txid);
    const inscription = parseInscriptionEnvelope(tx.outputs[0]!.script);
    expect(inscription).not.toBeNull();
    const json = JSON.parse(
      Buffer.from(inscription!.data, 'hex').toString('utf-8'),
    );
    expect(json.op).toBe('transfer');
    expect(json.amt).toBe('50');

    // Spend the transfer UTXO (P2PKH unlock)
    const { txid: spendTxid } = await contract.call(
      'unlock', [null, null], provider, signer,
    );
    expect(spendTxid).toBeTruthy();
    expect(spendTxid.length).toBe(64);
  });

  it('should round-trip BSV-20 inscription via fromTxId', async () => {
    const artifact = compileContract('examples/ts/bsv20-token/BSV20Token.runar.ts');

    const provider = createProvider();
    const { signer, pubKeyHash } = await createFundedWallet(provider);

    const contract = new RunarContract(artifact, [pubKeyHash]);
    contract.withInscription(BSV20.deploy({
      tick: 'TEST',
      max: '1000',
      dec: '8',
    }));

    const { txid } = await contract.deploy(provider, signer, { satoshis: 1 });

    // Reconnect and verify inscription persists
    const reconnected = await RunarContract.fromTxId(artifact, txid, 0, provider);
    expect(reconnected.inscription).not.toBeNull();
    expect(reconnected.inscription!.contentType).toBe('application/bsv-20');
    expect(reconnected.getLockingScript()).toBe(contract.getLockingScript());
  });
});
