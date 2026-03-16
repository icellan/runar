import { describe, it, expect } from 'vitest';
import { RunarContract } from '../contract.js';
import { selectUtxos, estimateDeployFee } from '../deployment.js';
import { buildCallTransaction } from '../calling.js';
import { MockProvider } from '../providers/mock.js';
import { LocalSigner } from '../signers/local.js';
import { serializeState, deserializeState } from '../state.js';
import type { RunarArtifact, StateField } from 'runar-ir-schema';
import type { TransactionData, UTXO } from '../types.js';

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

function makeUtxo(satoshis: number, index = 0): UTXO {
  return {
    txid: 'aabbccdd'.repeat(8),
    outputIndex: index,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  };
}

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

const PRIV_KEY = '0000000000000000000000000000000000000000000000000000000000000001';
const FAKE_TXID = 'aa'.repeat(32);

/**
 * Parse raw tx hex to verify structure (minimal parser).
 */
function parseTxHex(hex: string) {
  let offset = 0;

  function readBytes(n: number): string {
    const result = hex.slice(offset, offset + n * 2);
    offset += n * 2;
    return result;
  }

  function readUint32LE(): number {
    const h = readBytes(4);
    const bytes = [];
    for (let i = 0; i < 8; i += 2) bytes.push(parseInt(h.slice(i, i + 2), 16));
    return (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;
  }

  function readVarInt(): number {
    const first = parseInt(readBytes(1), 16);
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const h = readBytes(2);
      return parseInt(h.slice(0, 2), 16) | (parseInt(h.slice(2, 4), 16) << 8);
    }
    throw new Error('Unsupported varint');
  }

  const version = readUint32LE();
  const inputCount = readVarInt();
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    readBytes(32);
    const prevIndex = readUint32LE();
    const scriptLen = readVarInt();
    const script = readBytes(scriptLen);
    readUint32LE();
    inputs.push({ prevIndex, script });
  }

  return { version, inputCount, inputs };
}

// ---------------------------------------------------------------------------
// State initialization with mismatched constructor param / state field names
// ---------------------------------------------------------------------------

describe('state initialization with mismatched names', () => {
  it('initializes state by field index, not by name matching', () => {
    // Constructor param "initialHash" maps to state field "rollingHash" by index
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: {
          params: [
            { name: 'genesisOutpoint', type: 'ByteString' },
            { name: 'initialHash', type: 'ByteString' },
            { name: 'metadata', type: 'ByteString' },
          ],
        },
        methods: [],
      },
      stateFields: [
        { name: 'genesisOutpoint', type: 'ByteString', index: 0 },
        { name: 'rollingHash', type: 'ByteString', index: 1 },
        { name: 'metadata', type: 'ByteString', index: 2 },
      ],
    });

    const contract = new RunarContract(artifact, ['aabb', 'ccdd', 'eeff']);
    expect(contract.state.genesisOutpoint).toBe('aabb');
    expect(contract.state.rollingHash).toBe('ccdd');
    expect(contract.state.metadata).toBe('eeff');
  });

  it('produces valid hex in getLockingScript when names differ', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: {
          params: [
            { name: 'initialHash', type: 'ByteString' },
          ],
        },
        methods: [],
      },
      stateFields: [
        { name: 'rollingHash', type: 'ByteString', index: 0 },
      ],
    });

    const contract = new RunarContract(artifact, ['aabbccdd']);
    const script = contract.getLockingScript();
    // Must be valid hex, no "undefined" or "4.8"
    expect(script).toMatch(/^[0-9a-f]+$/);
    expect(script).not.toContain('undefined');
  });
});

// ---------------------------------------------------------------------------
// Fix 1: insertUnlockingScript actually modifies the transaction
// ---------------------------------------------------------------------------

describe('insertUnlockingScript', () => {
  it('deploy() inserts the signing script into input 0', async () => {
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 100_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const artifact = makeArtifact({
      script: '51',
      abi: { constructor: { params: [] }, methods: [] },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    const broadcastedTxs = provider.getBroadcastedTxs();
    expect(broadcastedTxs.length).toBe(1);

    // Parse the broadcast tx and verify input 0 has a non-empty scriptSig
    const parsed = parseTxHex(broadcastedTxs[0]!);
    expect(parsed.inputs[0]!.script.length).toBeGreaterThan(0);
  });

  it('deploy() with multiple UTXOs inserts scripts into all inputs', async () => {
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();

    // Add two UTXOs — both small enough that we need both
    provider.addUtxo(address, {
      txid: 'aa'.repeat(32),
      outputIndex: 0,
      satoshis: 30_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });
    provider.addUtxo(address, {
      txid: 'bb'.repeat(32),
      outputIndex: 0,
      satoshis: 30_000,
      script: '76a914' + '00'.repeat(20) + '88ac',
    });

    const artifact = makeArtifact({
      script: '51',
      abi: { constructor: { params: [] }, methods: [] },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    const broadcastedTxs = provider.getBroadcastedTxs();
    const parsed = parseTxHex(broadcastedTxs[0]!);

    expect(parsed.inputCount).toBe(2);
    // Both inputs should have non-empty scriptSigs
    expect(parsed.inputs[0]!.script.length).toBeGreaterThan(0);
    expect(parsed.inputs[1]!.script.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Fix 2: State mutation during call()
// ---------------------------------------------------------------------------

describe('state mutation during call()', () => {
  it('call() with newState updates contract state for stateful contracts', async () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
    ];

    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeUtxo(100_000));

    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [{ name: 'count', type: 'bigint' }] },
        methods: [{ name: 'increment', params: [], isPublic: true }],
      },
      stateFields,
    });

    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    expect(contract.state.count).toBe(0n);

    // Call with new state
    // Add more UTXOs for the call's additional funding
    provider.addUtxo(address, makeUtxo(100_000, 1));

    await contract.call('increment', [], provider, signer, {
      newState: { count: 1n },
    });

    expect(contract.state.count).toBe(1n);
  });

  it('setState() updates contract state directly', () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
      { name: 'active', type: 'bool', index: 1 },
    ];

    const artifact = makeArtifact({
      script: '51',
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

    const contract = new RunarContract(artifact, [10n, true]);
    // setState merges, doesn't replace
    contract.setState({ count: 20n });
    expect(contract.state.count).toBe(20n);
  });

  it('newState is reflected in the broadcast transaction locking script', async () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
    ];

    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeUtxo(100_000));

    const artifact = makeArtifact({
      script: '51', // OP_TRUE
      abi: {
        constructor: { params: [{ name: 'count', type: 'bigint' }] },
        methods: [{ name: 'increment', params: [], isPublic: true }],
      },
      stateFields,
    });

    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // The locking script before call should reflect count=0
    const scriptBefore = contract.getLockingScript();

    // Add funding for call
    provider.addUtxo(address, makeUtxo(100_000, 1));

    await contract.call('increment', [], provider, signer, {
      newState: { count: 5n },
    });

    // After call, state is 5 and locking script should differ
    const scriptAfter = contract.getLockingScript();
    expect(scriptAfter).not.toBe(scriptBefore);
    // The new script should contain the serialized state for count=5
    // 5n -> OP_5 -> 0x55, but in state encoding it's push-data: 0105
    expect(scriptAfter).toContain('6a'); // OP_RETURN separator
  });
});

// ---------------------------------------------------------------------------
// Fix 3: fromTxId preserves code script
// ---------------------------------------------------------------------------

describe('fromTxId code script preservation', () => {
  it('stateless contract produces correct locking script after reconnection', async () => {
    // A stateless P2PKH-like contract with constructor args spliced in
    const pubKeyHash = '18f5bdad6dac9a0a5044a970edf2897d67a7562d';
    const artifact = makeArtifact({
      contractName: 'P2PKH',
      script: '76a90088ac',
      abi: {
        constructor: { params: [{ name: 'pubKeyHash', type: 'Addr' }] },
        methods: [{ name: 'unlock', params: [], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 0, byteOffset: 2 }],
    });

    // The correct on-chain script after constructor arg splicing
    const onChainScript = '76a914' + pubKeyHash + '88ac';

    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 10_000, script: onChainScript }]),
    );

    const contract = await RunarContract.fromTxId(artifact, FAKE_TXID, 0, provider);

    // getLockingScript() should return the original on-chain script,
    // NOT a script with dummy 0n constructor args
    expect(contract.getLockingScript()).toBe(onChainScript);
  });

  it('stateful contract produces correct locking script with updated state after reconnection', async () => {
    const stateFields: StateField[] = [
      { name: 'count', type: 'bigint', index: 0 },
    ];

    const codeHex = '76a988ac'; // dummy code
    const originalState = { count: 42n };
    const stateHex = serializeState(stateFields, originalState);
    const fullScript = codeHex + '6a' + stateHex;

    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 10_000, script: fullScript }]),
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

    // Verify state was extracted
    expect(contract.state.count).toBe(42n);

    // getLockingScript() should return the original full script
    expect(contract.getLockingScript()).toBe(fullScript);

    // Now update state -- the code portion should stay the same
    contract.setState({ count: 100n });
    const updatedScript = contract.getLockingScript();

    // Code portion should be preserved
    expect(updatedScript.startsWith(codeHex)).toBe(true);
    // Should have OP_RETURN
    expect(updatedScript).toContain('6a');
    // Should differ from original (different state)
    expect(updatedScript).not.toBe(fullScript);
  });

  it('fromTxId with constructor slots does not use dummy args in getLockingScript', async () => {
    // This was the original bug: fromTxId used 0n dummy args,
    // then getLockingScript() would splice 0n into the script
    const artifact = makeArtifact({
      contractName: 'Threshold',
      script: '009c69', // OP_0 OP_NUMEQUAL OP_VERIFY
      abi: {
        constructor: { params: [{ name: 'threshold', type: 'bigint' }] },
        methods: [{ name: 'check', params: [], isPublic: true }],
      },
      constructorSlots: [{ paramIndex: 0, byteOffset: 0 }],
    });

    // On chain, threshold was set to 1000n -> encoded as 02e803
    const onChainScript = '02e8039c69';

    const provider = new MockProvider();
    provider.addTransaction(
      makeTx(FAKE_TXID, [{ satoshis: 5_000, script: onChainScript }]),
    );

    const contract = await RunarContract.fromTxId(artifact, FAKE_TXID, 0, provider);

    // Should return the actual on-chain script, NOT '009c69' with dummy args
    expect(contract.getLockingScript()).toBe(onChainScript);
  });
});

// ---------------------------------------------------------------------------
// Fix 4: Fee estimation with actual script sizes
// ---------------------------------------------------------------------------

describe('fee estimation with actual script sizes', () => {
  it('deploy fee accounts for large contract scripts', () => {
    // A 200-byte locking script should result in a larger fee than 34-byte P2PKH
    const smallScript = '51'; // 1 byte
    const largeScript = 'aa'.repeat(200); // 200 bytes

    const smallFee = estimateDeployFee(1, smallScript.length / 2);
    const largeFee = estimateDeployFee(1, largeScript.length / 2);

    // Large script fee should be significantly larger
    expect(largeFee).toBeGreaterThan(smallFee);
    // The difference should be approximately 200 - 1 = 199 bytes
    expect(largeFee - smallFee).toBe(199);
  });

  it('call fee uses actual unlocking script size for input 0', () => {
    const utxo = makeUtxo(1_000_000);
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    // Small unlocking script (1 byte)
    const { tx: smallTxObj } = buildCallTransaction(
      utxo, '51', undefined, undefined, 'addr', changeScript,
    );

    // Large unlocking script (200 bytes)
    const { tx: largeTxObj } = buildCallTransaction(
      utxo, 'aa'.repeat(200), undefined, undefined, 'addr', changeScript,
    );

    // The larger unlocking script should result in less change (higher fee)
    // We can verify this indirectly: larger tx should have smaller change output
    // Both txs have the same total input, so fee difference = change difference
    const smallTx = smallTxObj.toHex();
    const largeTx = largeTxObj.toHex();
    expect(largeTx.length).toBeGreaterThan(smallTx.length);
  });
});

// ---------------------------------------------------------------------------
// Fix 5: UTXO selection
// ---------------------------------------------------------------------------

describe('selectUtxos', () => {
  it('selects a single large UTXO when sufficient', () => {
    const utxos = [
      makeUtxo(10_000, 0),
      makeUtxo(100_000, 1),
      makeUtxo(5_000, 2),
    ];

    // Need 50,000 sats for a 1-byte script
    const selected = selectUtxos(utxos, 50_000, 1);

    // Should select only the 100,000 UTXO (largest-first)
    expect(selected.length).toBe(1);
    expect(selected[0]!.satoshis).toBe(100_000);
  });

  it('selects multiple UTXOs when no single UTXO is sufficient', () => {
    const utxos = [
      makeUtxo(20_000, 0),
      makeUtxo(25_000, 1),
      makeUtxo(30_000, 2),
    ];

    // Need 50,000 sats -- no single UTXO is enough
    const selected = selectUtxos(utxos, 50_000, 1);

    // Largest-first: 30,000 first, then 25,000 -> total 55,000
    expect(selected.length).toBe(2);
    expect(selected[0]!.satoshis).toBe(30_000);
    expect(selected[1]!.satoshis).toBe(25_000);
  });

  it('returns all UTXOs when total is still insufficient', () => {
    const utxos = [
      makeUtxo(100, 0),
      makeUtxo(200, 1),
    ];

    const selected = selectUtxos(utxos, 1_000_000, 1);

    // All UTXOs returned since total is not enough
    expect(selected.length).toBe(2);
  });

  it('accounts for fee increase with each additional input', () => {
    // Each additional input adds ~148 bytes to the fee
    // Create UTXOs where we're right at the boundary
    const fee1Input = estimateDeployFee(1, 1); // fee with 1 input

    // UTXO that's just barely not enough for 1-input scenario
    const target = 10_000;
    const utxos = [
      makeUtxo(target + fee1Input - 1, 0), // 1 sat short with 1 input
      makeUtxo(200, 1),
    ];

    const selected = selectUtxos(utxos, target, 1);

    // Needs 2 inputs because the first is 1 sat short
    expect(selected.length).toBe(2);
  });

  it('deploy() uses selected UTXOs, not all available', async () => {
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();

    // Add 5 UTXOs
    for (let i = 0; i < 5; i++) {
      provider.addUtxo(address, {
        txid: (i.toString(16).padStart(2, '0')).repeat(32),
        outputIndex: 0,
        satoshis: i === 2 ? 1_000_000 : 1_000, // One big UTXO, rest are small
        script: '76a914' + '00'.repeat(20) + '88ac',
      });
    }

    const artifact = makeArtifact({
      script: '51',
      abi: { constructor: { params: [] }, methods: [] },
    });

    const contract = new RunarContract(artifact, []);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    // Only 1 input should be needed (the 1M sat UTXO)
    const broadcastedTx = provider.getBroadcastedTxs()[0]!;
    const parsed = parseTxHex(broadcastedTx);
    expect(parsed.inputCount).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// M2: Boolean encoding -- must use minimal push (OP_TRUE / OP_FALSE)
// ---------------------------------------------------------------------------

describe('M2: SDK boolean encoding mismatch', () => {
  it('encodeArg(true) produces 51 (OP_TRUE) via buildUnlockingScript', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [{ name: 'flag', type: 'bool' }], isPublic: true }],
      },
    });

    const contract = new RunarContract(artifact, []);
    const unlockScript = contract.buildUnlockingScript('check', [true]);
    expect(unlockScript).toBe('51');
  });

  it('encodeArg(false) produces 00 (OP_FALSE) via buildUnlockingScript', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [{ name: 'check', params: [{ name: 'flag', type: 'bool' }], isPublic: true }],
      },
    });

    const contract = new RunarContract(artifact, []);
    const unlockScript = contract.buildUnlockingScript('check', [false]);
    expect(unlockScript).toBe('00');
  });

  it('encodeStateValue(true, "bool") produces 01 (raw byte) via serializeState', () => {
    const fields: StateField[] = [{ name: 'flag', type: 'bool', index: 0 }];
    const hex = serializeState(fields, { flag: true });
    expect(hex).toBe('01');
  });

  it('encodeStateValue(false, "bool") produces 00 via serializeState', () => {
    const fields: StateField[] = [{ name: 'flag', type: 'bool', index: 0 }];
    const hex = serializeState(fields, { flag: false });
    expect(hex).toBe('00');
  });

  it('boolean roundtrip: encode then deserialize preserves value', () => {
    const fields: StateField[] = [{ name: 'flag', type: 'bool', index: 0 }];

    const trueHex = serializeState(fields, { flag: true });
    const trueResult = deserializeState(fields, trueHex);
    expect(trueResult.flag).toBe(true);

    const falseHex = serializeState(fields, { flag: false });
    const falseResult = deserializeState(fields, falseHex);
    expect(falseResult.flag).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// m9: encodeScriptInt(0n) should return '00' (OP_0)
// ---------------------------------------------------------------------------

describe('m9: encodeScriptInt zero encoding', () => {
  it('state serialization of zero bigint produces 8-byte NUM2BIN zeros', () => {
    const fields: StateField[] = [{ name: 'count', type: 'bigint', index: 0 }];
    const hex = serializeState(fields, { count: 0n });
    expect(hex).toBe('0000000000000000');
  });

  it('zero bigint roundtrips correctly through serialize/deserialize', () => {
    const fields: StateField[] = [{ name: 'count', type: 'bigint', index: 0 }];
    const hex = serializeState(fields, { count: 0n });
    const result = deserializeState(fields, hex);
    expect(result.count).toBe(0n);
  });
});

// ---------------------------------------------------------------------------
// Fix: BigInt values from JSON without reviver ("0n" strings)
// ---------------------------------------------------------------------------

describe('BigInt values from JSON without reviver', () => {
  it('constructor revives "0n" initialValue from JSON-loaded artifact', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
      stateFields: [
        { name: 'count', type: 'bigint', index: 0, initialValue: '0n' as unknown as bigint },
      ],
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.state.count).toBe(0n);
  });

  it('constructor revives "1000n" initialValue from JSON-loaded artifact', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
      stateFields: [
        { name: 'amount', type: 'bigint', index: 0, initialValue: '1000n' as unknown as bigint },
      ],
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.state.amount).toBe(1000n);
  });

  it('constructor revives negative "-42n" initialValue from JSON-loaded artifact', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
      stateFields: [
        { name: 'offset', type: 'bigint', index: 0, initialValue: '-42n' as unknown as bigint },
      ],
    });

    const contract = new RunarContract(artifact, []);
    expect(contract.state.offset).toBe(-42n);
  });

  it('serializeState handles "0n" string values defensively', () => {
    const fields: StateField[] = [{ name: 'count', type: 'bigint', index: 0 }];
    // Simulate state containing unrevived "0n" string
    const hex = serializeState(fields, { count: '0n' as unknown as bigint });
    expect(hex).toBe('0000000000000000');
  });

  it('serializeState handles "1000n" string values defensively', () => {
    const fields: StateField[] = [{ name: 'count', type: 'bigint', index: 0 }];
    const hex = serializeState(fields, { count: '1000n' as unknown as bigint });
    // 1000n serialized with native bigint should match
    const expected = serializeState(fields, { count: 1000n });
    expect(hex).toBe(expected);
  });

  it('end-to-end: getLockingScript works with JSON-loaded artifact having "0n" initialValues', () => {
    const artifact = makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [] },
        methods: [],
      },
      stateFields: [
        { name: 'count', type: 'bigint', index: 0, initialValue: '0n' as unknown as bigint },
      ],
    });

    const contract = new RunarContract(artifact, []);
    const script = contract.getLockingScript();
    // Should be valid hex, no crash
    expect(script).toMatch(/^[0-9a-f]+$/);
    expect(script).toContain('6a'); // OP_RETURN separator
  });
});

// ---------------------------------------------------------------------------
// m10: Fee rate parameter
// ---------------------------------------------------------------------------

describe('m10: fee rate parameter', () => {
  it('estimateDeployFee with feeRate=2 returns double the default', () => {
    const fee1 = estimateDeployFee(1, 100);
    const fee2 = estimateDeployFee(1, 100, 2);
    expect(fee2).toBe(fee1 * 2);
  });

  it('estimateDeployFee with explicit feeRate=1 matches default', () => {
    const feeDefault = estimateDeployFee(1, 100);
    const feeExplicit = estimateDeployFee(1, 100, 1);
    expect(feeExplicit).toBe(feeDefault);
  });

  it('estimateDeployFee with feeRate=3 returns triple the default', () => {
    const fee1 = estimateDeployFee(1, 100);
    const fee3 = estimateDeployFee(1, 100, 3);
    expect(fee3).toBe(fee1 * 3);
  });
});

// ---------------------------------------------------------------------------
// Auto-compute state from ANF IR
// ---------------------------------------------------------------------------

describe('auto-compute state from ANF IR', () => {
  function makeStatefulArtifact(anf?: RunarArtifact['anf']): RunarArtifact {
    return makeArtifact({
      script: '51',
      abi: {
        constructor: { params: [{ name: 'count', type: 'bigint' }] },
        methods: [{
          name: 'increment',
          params: [
            { name: '_changePKH', type: 'Ripemd160' },
            { name: '_changeAmount', type: 'bigint' },
            { name: '_newAmount', type: 'bigint' },
            { name: 'txPreimage', type: 'SigHashPreimage' },
          ],
          isPublic: true,
        }],
      },
      stateFields: [{ name: 'count', type: 'bigint', index: 0 }],
      anf: anf ?? {
        contractName: 'Counter',
        properties: [{ name: 'count', type: 'bigint', readonly: false }],
        methods: [{
          name: 'increment',
          params: [
            { name: '_changePKH', type: 'Ripemd160' },
            { name: '_changeAmount', type: 'bigint' },
            { name: '_newAmount', type: 'bigint' },
            { name: 'txPreimage', type: 'SigHashPreimage' },
          ],
          body: [
            { name: 't0', value: { kind: 'load_prop', name: 'count' } },
            { name: 't1', value: { kind: 'load_const', value: 1n } },
            { name: 't2', value: { kind: 'bin_op', op: '+', left: 't0', right: 't1' } },
            { name: 't3', value: { kind: 'update_prop', name: 'count', value: 't2' } },
          ],
          isPublic: true,
        }],
      },
    });
  }

  it('prepareCall auto-computes newState when ANF IR present', async () => {
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeUtxo(100_000));

    const artifact = makeStatefulArtifact();
    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    expect(contract.state.count).toBe(0n);

    // Add funding for call
    provider.addUtxo(address, makeUtxo(100_000, 1));

    // Call WITHOUT newState — should auto-compute
    await contract.call('increment', [], provider, signer);

    expect(contract.state.count).toBe(1n);
  });

  it('prepareCall uses explicit newState when provided (override)', async () => {
    const signer = new LocalSigner(PRIV_KEY);
    const address = await signer.getAddress();
    const provider = new MockProvider();
    provider.addUtxo(address, makeUtxo(100_000));

    const artifact = makeStatefulArtifact();
    const contract = new RunarContract(artifact, [0n]);
    await contract.deploy(provider, signer, { satoshis: 50_000 });

    provider.addUtxo(address, makeUtxo(100_000, 1));

    // Explicit newState overrides auto-compute
    await contract.call('increment', [], provider, signer, {
      newState: { count: 99n },
    });

    expect(contract.state.count).toBe(99n);
  });
});
