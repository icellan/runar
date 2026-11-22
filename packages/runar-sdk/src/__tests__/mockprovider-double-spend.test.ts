/**
 * MockProvider must refuse a double spend.
 *
 * `broadcast()` validated every input on the real @bsv/sdk Spend, but it never
 * recorded which outpoints a broadcast had consumed, so a SECOND, different
 * transaction spending an outpoint an earlier broadcast already spent was
 * acked. A node refuses that (txn-mempool-conflict / missing inputs), so a test
 * or simulation on the mock could "succeed" at a spend the network rejects.
 */
import { describe, it, expect } from 'vitest';
import { Transaction, UnlockingScript, LockingScript } from '@bsv/sdk';
import { MockProvider } from '../providers/mock.js';

const FUNDING_TXID = 'ab'.repeat(32);

function spend(txid: string, vout: number, outSats: number): Transaction {
  const tx = new Transaction();
  tx.addInput({ sourceTXID: txid, sourceOutputIndex: vout, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
  tx.addOutput({ satoshis: outSats, lockingScript: LockingScript.fromHex('51') });
  return tx;
}

/** Deploy: broadcast a tx creating an OP_TRUE output, return its txid. */
async function deploy(provider: MockProvider): Promise<string> {
  provider.addUtxo('funder', { txid: FUNDING_TXID, outputIndex: 0, satoshis: 10_000, script: '51' });
  return provider.broadcast(spend(FUNDING_TXID, 0, 9_000));
}

describe('MockProvider refuses a double spend', () => {
  it('refuses a different tx spending an outpoint an earlier broadcast spent', async () => {
    const provider = new MockProvider();
    const deployTxid = await deploy(provider);
    const first = spend(deployTxid, 0, 8_000);
    await provider.broadcast(first);

    const conflicting = spend(deployTxid, 0, 7_000);
    expect(conflicting.id('hex')).not.toBe(first.id('hex'));
    await expect(provider.broadcast(conflicting)).rejects.toThrow(/already spent/);
    // The refused tx left no trace.
    expect(provider.getBroadcastedTxs()).toHaveLength(2);
    await expect(provider.getTransaction(conflicting.id('hex') as string)).rejects.toThrow();
  });

  it('refuses a tx that spends the same outpoint twice', async () => {
    const provider = new MockProvider();
    const deployTxid = await deploy(provider);
    const tx = spend(deployTxid, 0, 8_000);
    tx.addInput({ sourceTXID: deployTxid, sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff });
    await expect(provider.broadcast(tx)).rejects.toThrow(/more than once/);
  });

  it('getUtxos no longer lists an outpoint an accepted broadcast spent', async () => {
    const provider = new MockProvider();
    provider.addUtxo('funder', { txid: FUNDING_TXID, outputIndex: 1, satoshis: 5_000, script: '51' });
    await deploy(provider);
    expect((await provider.getUtxos('funder')).map((u) => u.outputIndex)).toEqual([1]);
  });

  it('a refused broadcast does not mark its inputs spent', async () => {
    const provider = new MockProvider();
    const deployTxid = await deploy(provider);
    // Underfunded: refused by validation, so the outpoint stays unspent.
    await expect(provider.broadcast(spend(deployTxid, 0, 50_000))).rejects.toThrow();
    await expect(provider.broadcast(spend(deployTxid, 0, 8_000))).resolves.toMatch(/^[0-9a-f]{64}$/);
  });

  it('re-broadcasting the identical tx is not a double spend', async () => {
    const provider = new MockProvider();
    const deployTxid = await deploy(provider);
    const tx = spend(deployTxid, 0, 8_000);
    const a = await provider.broadcast(tx);
    await expect(provider.broadcast(tx)).resolves.toBe(a);
  });
});
