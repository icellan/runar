import { describe, it, expect } from 'vitest';
import { MockProvider } from '../providers/mock.js';
import type { Transaction, UTXO } from '../types.js';

// ---------------------------------------------------------------------------
// MockProvider: transactions
// ---------------------------------------------------------------------------

describe('MockProvider: transactions', () => {
  it('add a transaction and get it back', async () => {
    const provider = new MockProvider();
    const tx: Transaction = {
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
    const rawTx = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a010000001976a914aabbccdd88ac00000000';
    const txid = await provider.broadcast(rawTx);
    expect(txid).toBeDefined();
    expect(typeof txid).toBe('string');
    expect(txid.length).toBe(64); // txid should be 64 hex chars
  });

  it('records broadcasted transactions', async () => {
    const provider = new MockProvider();
    const rawTx1 = 'deadbeef';
    const rawTx2 = 'cafebabe';

    await provider.broadcast(rawTx1);
    await provider.broadcast(rawTx2);

    const broadcasted = provider.getBroadcastedTxs();
    expect(broadcasted.length).toBe(2);
    expect(broadcasted[0]).toBe(rawTx1);
    expect(broadcasted[1]).toBe(rawTx2);
  });

  it('returns different txids for different broadcasts', async () => {
    const provider = new MockProvider();
    const txid1 = await provider.broadcast('tx1');
    const txid2 = await provider.broadcast('tx2');
    expect(txid1).not.toBe(txid2);
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
    const tx: Transaction = {
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
    const tx: Transaction = {
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
