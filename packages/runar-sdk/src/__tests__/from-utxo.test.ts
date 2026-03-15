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

const FAKE_TXID = 'aa'.repeat(32);

function makeTx(
  txid: string,
  outputs: Array<{ satoshis: number; script: string }>,
): TransactionData {
  return {
    txid,
    version: 1,
    inputs: [{ txid: '00'.repeat(32), outputIndex: 0, script: '', sequence: 0xffffffff }],
    outputs,
    locktime: 0,
  };
}

// ---------------------------------------------------------------------------
// RunarContract.fromUtxo
// ---------------------------------------------------------------------------

describe('RunarContract.fromUtxo', () => {
  it('reconnects to a stateful contract and extracts state', () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
      { name: 'active', type: 'bool', index: 1 },
    ];

    const codeHex = '76a988ac';
    const stateValues = { count: 42n, active: true };
    const stateHex = serializeState(stateFields, stateValues);
    const fullScript = codeHex + '6a' + stateHex;

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

    const contract = RunarContract.fromUtxo(artifact, {
      txid: FAKE_TXID,
      outputIndex: 0,
      satoshis: 10_000,
      script: fullScript,
    });

    expect(contract.state.count).toBe(42n);
    expect(contract.state.active).toBe(true);
    expect(contract.getUtxo()?.txid).toBe(FAKE_TXID);
    expect(contract.getUtxo()?.satoshis).toBe(10_000);
  });

  it('reconnects to a stateless contract', () => {
    const simpleScript = '51'; // OP_TRUE

    const artifact = makeArtifact({
      script: simpleScript,
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'spend', params: [], isPublic: true }],
      },
    });

    const contract = RunarContract.fromUtxo(artifact, {
      txid: FAKE_TXID,
      outputIndex: 2,
      satoshis: 5_000,
      script: simpleScript,
    });

    expect(Object.keys(contract.state).length).toBe(0);
    expect(contract.getUtxo()?.outputIndex).toBe(2);
  });

  it('produces correct locking script after reconnection', () => {
    const stateFields: StateField[] = [
      { name: 'value', type: 'bigint', index: 0 },
    ];

    const codeHex = 'aabb';
    const stateValues = { value: 100n };
    const stateHex = serializeState(stateFields, stateValues);
    const fullScript = codeHex + '6a' + stateHex;

    const artifact = makeArtifact({
      script: codeHex,
      abi: {
        constructor: { params: [{ name: 'value', type: 'bigint' }] },
        methods: [],
      },
      stateFields,
    });

    const contract = RunarContract.fromUtxo(artifact, {
      txid: FAKE_TXID,
      outputIndex: 0,
      satoshis: 1000,
      script: fullScript,
    });

    // getLockingScript should produce the same full script
    expect(contract.getLockingScript()).toBe(fullScript);
  });

  it('fromTxId delegates to fromUtxo', async () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
    ];

    const codeHex = '76a988ac';
    const stateValues = { count: 7n };
    const stateHex = serializeState(stateFields, stateValues);
    const fullScript = codeHex + '6a' + stateHex;

    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 1000, script: fullScript }]),
    );

    const artifact = makeArtifact({
      script: codeHex,
      abi: {
        constructor: { params: [{ name: 'count', type: 'bigint' }] },
        methods: [],
      },
      stateFields,
    });

    const contract = await RunarContract.fromTxId(artifact, FAKE_TXID, 0, provider);
    expect(contract.state.count).toBe(7n);
    expect(contract.getUtxo()?.txid).toBe(FAKE_TXID);
  });
});
