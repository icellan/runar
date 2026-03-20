import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { MockProvider } from '../providers/mock.js';
import { RPCProvider } from '../providers/rpc-provider.js';
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

  it('returns the same txid for the same transaction broadcasted twice (deterministic) (row 411)', async () => {
    const provider = new MockProvider();
    // Build two identical transactions
    const tx1 = makeBsvTx('5151');
    const tx2 = makeBsvTx('5151');
    // They should have the same hex
    expect(tx1.toHex()).toBe(tx2.toHex());

    const txid1 = await provider.broadcast(tx1);
    const txid2 = await provider.broadcast(tx2);
    // Same transaction → same txid
    expect(txid1).toBe(txid2);
    expect(txid1).toHaveLength(64);
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

// ---------------------------------------------------------------------------
// RPCProvider unit tests (using mocked fetch)
// ---------------------------------------------------------------------------

/** Build a minimal mock fetch that returns a JSON-RPC success response. */
function makeMockFetch(result: unknown) {
  return vi.fn().mockResolvedValue({
    json: async () => ({ result, error: null }),
  } as unknown as Response);
}

describe('RPCProvider: configuration', () => {
  it('defaults to testnet network (row 413)', () => {
    const provider = new RPCProvider('http://localhost:8332', 'user', 'pass');
    expect(provider.getNetwork()).toBe('testnet');
  });

  it('respects network option override', () => {
    const provider = new RPCProvider('http://localhost:8332', 'user', 'pass', { network: 'mainnet' });
    expect(provider.getNetwork()).toBe('mainnet');
  });
});

describe('RPCProvider: broadcast (row 414)', () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(global, 'fetch');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('broadcast sends raw transaction hex to RPC endpoint', async () => {
    const txid = 'ab'.repeat(32);
    fetchSpy.mockResolvedValue({
      json: async () => ({ result: txid, error: null }),
    } as unknown as Response);

    const provider = new RPCProvider('http://localhost:8332', 'testuser', 'testpass');
    const tx = makeBsvTx();
    const rawHex = tx.toHex();

    const result = await provider.broadcast(tx);

    expect(result).toBe(txid);
    // Verify fetch was called with the raw transaction hex in the body
    expect(fetchSpy).toHaveBeenCalledOnce();
    const callArgs = fetchSpy.mock.calls[0]!;
    const body = JSON.parse(callArgs[1]!.body as string) as Record<string, unknown>;
    expect(body.method).toBe('sendrawtransaction');
    expect(body.params).toEqual([rawHex]);
  });

  it('sets Basic auth header from credentials (row 412)', async () => {
    const txid = 'cc'.repeat(32);
    fetchSpy.mockResolvedValue({
      json: async () => ({ result: txid, error: null }),
    } as unknown as Response);

    const provider = new RPCProvider('http://localhost:8332', 'myuser', 'mypass');
    await provider.broadcast(makeBsvTx());

    const callArgs = fetchSpy.mock.calls[0]!;
    const headers = callArgs[1]!.headers as Record<string, string>;
    const expectedAuth = `Basic ${Buffer.from('myuser:mypass').toString('base64')}`;
    expect(headers['Authorization']).toBe(expectedAuth);
  });
});

describe('RPCProvider: getTransaction (row 415)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('parses getTransaction output: txid, outputs, satoshis', async () => {
    const mockRpcResult = {
      hex: '0100000001deadbeef',
      vout: [
        {
          value: 0.0001,
          scriptPubKey: { hex: '76a914aabbccdd88ac' },
        },
        {
          value: 0.0002,
          scriptPubKey: { hex: '76a914ccddccdd88ac' },
        },
      ],
    };

    vi.spyOn(global, 'fetch').mockResolvedValue({
      json: async () => ({ result: mockRpcResult, error: null }),
    } as unknown as Response);

    const provider = new RPCProvider('http://localhost:8332', 'user', 'pass');
    const txdata = await provider.getTransaction('ab'.repeat(32));

    expect(txdata.txid).toBe('ab'.repeat(32));
    expect(txdata.outputs).toHaveLength(2);
    expect(txdata.outputs[0]!.satoshis).toBe(10000);
    expect(txdata.outputs[0]!.script).toBe('76a914aabbccdd88ac');
    expect(txdata.outputs[1]!.satoshis).toBe(20000);
  });
});

describe('RPCProvider: getUtxos (row 416)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('parses listunspent response into UTXO array', async () => {
    const mockUtxoList = [
      {
        txid: 'aa'.repeat(32),
        vout: 0,
        amount: 0.0005,
        scriptPubKey: '76a914aabbccdd88ac',
      },
      {
        txid: 'bb'.repeat(32),
        vout: 2,
        amount: 0.001,
        scriptPubKey: '76a914bbccddee88ac',
      },
    ];

    vi.spyOn(global, 'fetch').mockResolvedValue({
      json: async () => ({ result: mockUtxoList, error: null }),
    } as unknown as Response);

    const provider = new RPCProvider('http://localhost:8332', 'user', 'pass');
    const utxos = await provider.getUtxos('1TestAddress');

    expect(utxos).toHaveLength(2);
    expect(utxos[0]!.txid).toBe('aa'.repeat(32));
    expect(utxos[0]!.outputIndex).toBe(0);
    expect(utxos[0]!.satoshis).toBe(50000);
    expect(utxos[1]!.txid).toBe('bb'.repeat(32));
    expect(utxos[1]!.outputIndex).toBe(2);
    expect(utxos[1]!.satoshis).toBe(100000);
  });
});

describe('RPCProvider: getFeeRate (row 417)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('getFeeRate returns 100 sat/KB (standard BSV relay fee)', async () => {
    const provider = new RPCProvider('http://localhost:8332', 'user', 'pass');
    const rate = await provider.getFeeRate();
    expect(rate).toBe(100);
  });
});
