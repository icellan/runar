import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { MockProvider } from '../providers/mock.js';
import { serializeState } from '../state.js';
import type { RunarArtifact, StateField } from 'runar-ir-schema';
import type { TransactionData } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeArtifact(
  overrides: Partial<RunarArtifact> & Pick<RunarArtifact, 'script' | 'abi'>,
): RunarArtifact {
  return {
    version: 'runar-v0.1.0',
    compilerVersion: '0.1.0',
    contractName: 'Test',
    asm: '',
    buildTimestamp: '2026-03-02T00:00:00.000Z',
    ...overrides,
  };
}

const FAKE_TXID = 'aa'.repeat(32); // 64 hex chars

function makeTx(
  txid: string,
  outputs: Array<{ satoshis: number; script: string }>,
): TransactionData {
  return {
    txid,
    version: 1,
    inputs: [
      {
        txid: '00'.repeat(32),
        outputIndex: 0,
        script: '',
        sequence: 0xffffffff,
      },
    ],
    outputs,
    locktime: 0,
  };
}

// ---------------------------------------------------------------------------
// RunarContract.fromTxId
// ---------------------------------------------------------------------------

describe('RunarContract.fromTxId', () => {
  it('reconnects to a stateful contract and extracts state', async () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
      { name: 'active', type: 'bool', index: 1 },
    ];

    // Build a locking script: <some code> + OP_RETURN + <serialized state>
    const codeHex = '76a988ac'; // some dummy code
    const stateValues = { count: 42n, active: true };
    const stateHex = serializeState(stateFields, stateValues);
    const fullScript = codeHex + '6a' + stateHex;

    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 10_000, script: fullScript }]),
    );

    const artifact = makeArtifact({
      script: codeHex,
      abi: {
        constructor: {
          params: [
            { name: 'count', type: 'bigint' },
            { name: 'active', type: 'bool' },
          ],
        },
        methods: [],
      },
      stateFields,
    });

    const contract = await RunarContract.fromTxId(
      artifact,
      FAKE_TXID,
      0,
      provider,
    );

    expect(contract.state.count).toBe(42n);
    expect(contract.state.active).toBe(true);
  });

  it('reconnects to a stateless contract', async () => {
    const provider = new MockProvider();
    const simpleScript = '51'; // OP_TRUE
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 5_000, script: simpleScript }]),
    );

    const artifact = makeArtifact({
      script: simpleScript,
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'spend', params: [], isPublic: true }],
      },
      // No stateFields — stateless contract
    });

    const contract = await RunarContract.fromTxId(
      artifact,
      FAKE_TXID,
      0,
      provider,
    );

    // State should be empty for stateless contracts
    expect(Object.keys(contract.state).length).toBe(0);
  });

  it('throws on out-of-range outputIndex', async () => {
    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 5_000, script: '51' }]),
    );

    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
    });

    // Transaction has 1 output (index 0). Request index 5.
    await expect(
      RunarContract.fromTxId(artifact, FAKE_TXID, 5, provider),
    ).rejects.toThrow('out of range');
  });

  // F-273: a negative outputIndex must be rejected with a clear error.
  // JS arrays do not support Python/Ruby-style negative indexing
  // (tx.outputs[-1] is `undefined`, not the last element), so this does not
  // silently bind to the wrong output the way Python/Ruby did — but without
  // an explicit `< 0` guard it crashes on `output.satoshis` with an
  // unrelated TypeError instead of RunarContract's own clear error.
  //
  // Proves: outputIndex=-1 throws RunarContract's own "out of range" Error
  // instead of an unrelated TypeError from indexing past the array.
  // Does not prove: behaviour for other negative indices, or for providers
  // other than MockProvider.
  it('throws a clear error on a negative outputIndex', async () => {
    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [
        { satoshis: 5_000, script: '51' },
        { satoshis: 9_999, script: '76a9140000000000000000000000000000000000000088ac' },
      ]),
    );

    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
    });

    await expect(
      RunarContract.fromTxId(artifact, FAKE_TXID, -1, provider),
    ).rejects.toThrow('out of range');
  });

  it('throws on unknown txid', async () => {
    const provider = new MockProvider();
    // Do NOT add any transactions.

    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
    });

    const unknownTxid = 'ff'.repeat(32);
    await expect(
      RunarContract.fromTxId(artifact, unknownTxid, 0, provider),
    ).rejects.toThrow('not found');
  });
});
