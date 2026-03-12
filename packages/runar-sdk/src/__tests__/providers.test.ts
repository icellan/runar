import { describe, it, expect } from 'vitest';
import { MockProvider } from '../providers/mock.js';
import { Transaction as BsvTransaction, LockingScript, UnlockingScript } from '@bsv/sdk';
import type { TransactionData, UTXO } from '../types.js';

/** Create a minimal valid BsvTransaction for broadcast testing. */
function makeBsvTx(marker?: string): BsvTransaction {
  const tx = new BsvTransaction();
  tx.addInput({
    sourceTXID: '00'.repeat(32),
    sourceOutputIndex: 0,
    unlockingScript: new UnlockingScript(),
    sequence: 0xffffffff,
  });
  tx.addOutput({
    satoshis: 50000,
    lockingScript: LockingScript.fromHex(marker || '51'),
  });
  return tx;
}

// ---------------------------------------------------------------------------
// MockProvider: transactions
// ---------------------------------------------------------------------------

describe('MockProvider: transactions', () => {
  it('add a transaction and get it back', async () => {
    const provider = new MockProvider();
    const tx: TransactionData = {
      txid: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      version: 1,
      inputs: [{
        txid: '0000000000000000000000000000000000000000000000000000000000000000',
        outputIndex: 0,
        script: '',
        sequence: 0xffffffff,
      }],
      outputs: [{
        satoshis: 10000,
        script: '76a914aabbccdd88ac',
      }],
      locktime: 0,
    };

    provider.addTransaction(tx);
    const retrieved = await provider.getTransaction(tx.txid);
    expect(retrieved.txid).toBe(tx.txid);
    expect(retrieved.version).toBe(1);
    expect(retrieved.outputs.length).toBe(1);
    expect(retrieved.outputs[0]!.satoshis).toBe(10000);
  });

  it('throws for unknown transaction', async () => {
    const provider = new MockProvider();
    await expect(
      provider.getTransaction('nonexistent'),
    ).rejects.toThrow('not found');
  });
});

// ---------------------------------------------------------------------------
// MockProvider: UTXOs
// ---------------------------------------------------------------------------

describe('MockProvider: UTXOs', () => {
  it('add a UTXO and get it back', async () => {
    const provider = new MockProvider();
    const address = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
    const utxo: UTXO = {
      txid: 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
      outputIndex: 0,
      satoshis: 50000,
      script: '76a914aabbccdd88ac',
    };

    provider.addUtxo(address, utxo);
    const utxos = await provider.getUtxos(address);
    expect(utxos.length).toBe(1);
    expect(utxos[0]!.txid).toBe(utxo.txid);
    expect(utxos[0]!.satoshis).toBe(50000);
  });

  it('returns empty array for unknown address', async () => {
    const provider = new MockProvider();
    const utxos = await provider.getUtxos('unknown-address');
    expect(utxos).toEqual([]);
  });

  it('accumulates multiple UTXOs for the same address', async () => {
    const provider = new MockProvider();
    const address = 'test-address';

    provider.addUtxo(address, {
      txid: 'tx1'.padEnd(64, '0'),
      outputIndex: 0,
      satoshis: 1000,
      script: 'aabb',
    });

    provider.addUtxo(address, {
      txid: 'tx2'.padEnd(64, '0'),
      outputIndex: 1,
      satoshis: 2000,
      script: 'ccdd',
    });

    const utxos = await provider.getUtxos(address);
    expect(utxos.length).toBe(2);
    expect(utxos[0]!.satoshis).toBe(1000);
    expect(utxos[1]!.satoshis).toBe(2000);
  });
});

// ---------------------------------------------------------------------------
// MockProvider: contract UTXOs
// ---------------------------------------------------------------------------

describe('MockProvider: contract UTXOs', () => {
  it('add and retrieve a contract UTXO', async () => {
    const provider = new MockProvider();
    const scriptHash = 'aabbccdd'.repeat(8);
    const utxo: UTXO = {
      txid: 'abc123'.padEnd(64, '0'),
      outputIndex: 0,
      satoshis: 100000,
      script: '51',
    };

    provider.addContractUtxo(scriptHash, utxo);
    const retrieved = await provider.getContractUtxo(scriptHash);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.satoshis).toBe(100000);
  });

  it('returns null for unknown script hash', async () => {
    const provider = new MockProvider();
    const result = await provider.getContractUtxo('nonexistent');
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// MockProvider: broadcast
// ---------------------------------------------------------------------------

describe('MockProvider: broadcast', () => {
  it('broadcast returns a txid', async () => {
    const provider = new MockProvider();
    const tx = makeBsvTx();
    const txid = await provider.broadcast(tx);
    expect(txid).toBeDefined();
    expect(typeof txid).toBe('string');
    expect(txid.length).toBe(64); // txid should be 64 hex chars
  });

  it('records broadcasted transactions', async () => {
    const provider = new MockProvider();
    const tx1 = makeBsvTx('5151'); // distinct script
    const tx2 = makeBsvTx('5252'); // distinct script

    await provider.broadcast(tx1);
    await provider.broadcast(tx2);

    const broadcasted = provider.getBroadcastedTxs();
    expect(broadcasted.length).toBe(2);
    expect(broadcasted[0]).toBe(tx1.toHex());
    expect(broadcasted[1]).toBe(tx2.toHex());
  });

  it('records broadcasted Transaction objects', async () => {
    const provider = new MockProvider();
    const tx = makeBsvTx();
    await provider.broadcast(tx);
    const txObjects = provider.getBroadcastedTxObjects();
    expect(txObjects.length).toBe(1);
    expect(txObjects[0]).toBe(tx);
  });

  it('returns different txids for different broadcasts', async () => {
    const provider = new MockProvider();
    const txid1 = await provider.broadcast(makeBsvTx('aa'));
    const txid2 = await provider.broadcast(makeBsvTx('bb'));
    expect(txid1).not.toBe(txid2);
  });

  it('auto-stores raw hex for getRawTransaction after broadcast', async () => {
    const provider = new MockProvider();
    const tx = makeBsvTx();
    const txid = await provider.broadcast(tx);
    const rawHex = await provider.getRawTransaction(txid);
    expect(rawHex).toBe(tx.toHex());
  });
});

// ---------------------------------------------------------------------------
// MockProvider: network
// ---------------------------------------------------------------------------

describe('MockProvider: network', () => {
  it('defaults to testnet', () => {
    const provider = new MockProvider();
    expect(provider.getNetwork()).toBe('testnet');
  });

  it('can be set to mainnet', () => {
    const provider = new MockProvider('mainnet');
    expect(provider.getNetwork()).toBe('mainnet');
  });
});

// ---------------------------------------------------------------------------
// MockProvider: getRawTransaction
// ---------------------------------------------------------------------------

describe('MockProvider: getRawTransaction', () => {
  it('returns raw hex when available', async () => {
    const provider = new MockProvider();
    const tx: TransactionData = {
      txid: 'aa'.repeat(32),
      version: 1,
      inputs: [],
      outputs: [{ satoshis: 10000, script: '51' }],
      locktime: 0,
      raw: '01000000deadbeef',
    };

    provider.addTransaction(tx);
    const rawHex = await provider.getRawTransaction(tx.txid);
    expect(rawHex).toBe('01000000deadbeef');
  });

  it('throws for unknown txid', async () => {
    const provider = new MockProvider();
    await expect(
      provider.getRawTransaction('nonexistent'),
    ).rejects.toThrow('not found');
  });

  it('throws when transaction has no raw hex', async () => {
    const provider = new MockProvider();
    const tx: TransactionData = {
      txid: 'bb'.repeat(32),
      version: 1,
      inputs: [],
      outputs: [{ satoshis: 5000, script: '51' }],
      locktime: 0,
    };

    provider.addTransaction(tx);
    await expect(
      provider.getRawTransaction(tx.txid),
    ).rejects.toThrow('no raw hex');
  });
});
