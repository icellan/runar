/**
 * `txToTransactionData` is public: a custom Provider that holds @bsv/sdk
 * Transactions (an overlay, an indexer, a local cache) answers
 * `getTransaction()` with the same TransactionData the SDK's own providers
 * and `deploy()` / `finalizeCall()` produce.
 *
 * Proves: the barrel exports the same function the SDK uses internally, and
 * it fills every field from the transaction, including an input's txid when
 * only its source transaction is attached.
 */
import { describe, it, expect } from 'vitest';
import { LockingScript, Transaction, UnlockingScript } from '@bsv/sdk';
import * as sdk from '../index.js';
import { txToTransactionData as internal } from '../providers/provider.js';

function parentAndChild(): { parent: Transaction; child: Transaction } {
  const parent = new Transaction();
  parent.addOutput({ lockingScript: LockingScript.fromHex('51'), satoshis: 1000 });

  const child = new Transaction();
  child.version = 2;
  child.lockTime = 500;
  child.addInput({
    sourceTransaction: parent,
    sourceOutputIndex: 0,
    unlockingScript: UnlockingScript.fromHex('0151'),
    sequence: 0xfffffffe,
  });
  child.addOutput({ lockingScript: LockingScript.fromHex('76a914' + '11'.repeat(20) + '88ac'), satoshis: 900 });
  return { parent, child };
}

describe('txToTransactionData is exported from runar-sdk', () => {
  it('is the function the SDK uses internally', () => {
    expect(sdk.txToTransactionData).toBe(internal);
  });

  it('projects a Transaction into TransactionData', () => {
    const { parent, child } = parentAndChild();
    const txid = child.id('hex');

    expect(sdk.txToTransactionData(txid, child)).toEqual({
      txid,
      version: 2,
      inputs: [{ txid: parent.id('hex'), outputIndex: 0, script: '0151', sequence: 0xfffffffe }],
      outputs: [{ satoshis: 900, script: '76a914' + '11'.repeat(20) + '88ac' }],
      locktime: 500,
      raw: child.toHex(),
    });
  });
});
