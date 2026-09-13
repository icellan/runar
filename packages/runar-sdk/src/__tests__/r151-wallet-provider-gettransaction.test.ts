/**
 * R-151 (CL-BUG-070): WalletProvider.getTransaction() returned an empty-shell
 * TransactionData on a cache miss or a parse failure.
 *
 *     // Minimal fallback
 *     return { txid, version: 1, inputs: [], outputs: [], locktime: 0 };
 *
 * A caller that asks for a transaction and gets back one with zero inputs, zero
 * outputs and no raw hex has no way to tell "this transaction has no outputs"
 * from "I could not find this transaction". The same shape was already fixed
 * once in this SDK — `txToTransactionData` (providers/provider.ts) is the C4
 * remediation — and the fix was never applied here.
 *
 * A provider that cannot answer must say so.
 */

import { describe, it, expect } from 'vitest';
import { Transaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import { WalletProvider } from '../providers/wallet-provider.js';
import type { Signer } from '../signers/signer.js';
import type { WalletClient } from '@bsv/sdk';

const stubSigner: Signer = {
  async getPublicKey() { return '02' + '11'.repeat(32); },
  async getAddress() { return '1BitcoinAddress'; },
  async sign() { return '00'.repeat(71); },
} as unknown as Signer;

const stubWallet = {} as unknown as WalletClient;

function provider(): WalletProvider {
  return new WalletProvider({ wallet: stubWallet, signer: stubSigner, basket: 'b' });
}

/** A real one-input, one-output transaction. */
function sampleTx(): Transaction {
  const tx = new Transaction();
  tx.version = 1;
  tx.addInput({
    sourceTXID: 'aa'.repeat(32),
    sourceOutputIndex: 0,
    sequence: 0xffffffff,
    unlockingScript: new UnlockingScript(),
  });
  tx.addOutput({ satoshis: 1234, lockingScript: new LockingScript() });
  tx.lockTime = 0;
  return tx;
}

describe('R-151: getTransaction must not invent an empty transaction', () => {
  it('rejects a cache miss instead of returning an empty shell', async () => {
    const missing = 'bb'.repeat(32);
    // The diagnosis must name the transaction it could not produce, so the
    // caller can tell a miss from an empty transaction.
    await expect(provider().getTransaction(missing)).rejects.toThrow(missing);
    await expect(provider().getTransaction(missing)).rejects.toThrow(/cache/i);
  });

  it('rejects unparseable cached hex instead of returning an empty shell', async () => {
    const p = provider();
    p.cacheTx('cc'.repeat(32), 'not-a-transaction');
    await expect(p.getTransaction('cc'.repeat(32))).rejects.toThrow();
  });

  it('still returns the real transaction when it is cached', async () => {
    const p = provider();
    const tx = sampleTx();
    const txid = tx.id('hex');
    p.cacheTx(txid, tx.toHex());

    const data = await p.getTransaction(txid);
    expect(data.txid).toBe(txid);
    expect(data.inputs).toHaveLength(1);
    expect(data.outputs).toHaveLength(1);
    expect(data.outputs[0]!.satoshis).toBe(1234);
    expect(data.raw).toBe(tx.toHex());
  });

  it('never returns a transaction with no raw hex', async () => {
    // The invariant behind all of the above: every TransactionData this
    // provider hands back describes bytes it actually has.
    const p = provider();
    const tx = sampleTx();
    p.cacheTx(tx.id('hex'), tx.toHex());
    const data = await p.getTransaction(tx.id('hex'));
    expect(data.raw).toBeTruthy();
  });
});
