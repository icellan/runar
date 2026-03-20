import { describe, it, expect } from 'vitest';
import { buildCallTransaction } from '../calling.js';
import type { UTXO } from '../types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUtxo(satoshis: number, index = 0): UTXO {
  return {
    txid: 'aabbccdd'.repeat(8), // 64 hex chars = 32 bytes
    outputIndex: index,
    satoshis,
    script: '76a914' + '00'.repeat(20) + '88ac',
  };
}

/**
 * Parse a raw transaction hex into its structural components.
 * Minimal parser for verification purposes.
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
    for (let i = 0; i < 8; i += 2) {
      bytes.push(parseInt(h.slice(i, i + 2), 16));
    }
    return (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0;
  }

  function readUint64LE(): number {
    const lo = readUint32LE();
    const hi = readUint32LE();
    return hi * 0x100000000 + lo;
  }

  function readVarInt(): number {
    const first = parseInt(readBytes(1), 16);
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const h = readBytes(2);
      const lo = parseInt(h.slice(0, 2), 16);
      const hi = parseInt(h.slice(2, 4), 16);
      return lo | (hi << 8);
    }
    throw new Error('Unsupported varint');
  }

  // Version
  const version = readUint32LE();

  // Input count
  const inputCount = readVarInt();

  // Inputs
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxid = readBytes(32);
    const prevIndex = readUint32LE();
    const scriptLen = readVarInt();
    const script = readBytes(scriptLen);
    const sequence = readUint32LE();
    inputs.push({ prevTxid, prevIndex, script, sequence });
  }

  // Output count
  const outputCount = readVarInt();

  // Outputs
  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const satoshis = readUint64LE();
    const scriptLen = readVarInt();
    const script = readBytes(scriptLen);
    outputs.push({ satoshis, script });
  }

  // Locktime
  const locktime = readUint32LE();

  return { version, inputCount, inputs, outputCount, outputs, locktime };
}

/**
 * Reverse hex byte order (for txid wire format: internal byte order is reversed).
 */
function reverseHex(hex: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    pairs.push(hex.slice(i, i + 2));
  }
  return pairs.reverse().join('');
}

// ---------------------------------------------------------------------------
// Basic transaction structure (Bitcoin protocol rules)
// ---------------------------------------------------------------------------

describe('buildCallTransaction — transaction structure', () => {
  it('produces version 1 and locktime 0 per Bitcoin protocol', () => {
    const utxo = makeUtxo(100000);
    const unlockingScript = '4830'.padEnd(144, 'aa'); // mock 72-byte sig push

    const { tx } = buildCallTransaction(utxo, unlockingScript);
    const parsed = parseTxHex(tx.toHex());

    expect(parsed.version).toBe(1);
    expect(parsed.locktime).toBe(0);
  });

  it('produces valid hex output', () => {
    const utxo = makeUtxo(100000);
    const { tx } = buildCallTransaction(utxo, '51');
    const txHex = tx.toHex();

    expect(txHex).toBeDefined();
    expect(txHex.length).toBeGreaterThan(0);
    expect(/^[0-9a-f]+$/.test(txHex)).toBe(true);
  });

  it('embeds the unlocking script in input 0 (not empty)', () => {
    const utxo = makeUtxo(100000);
    const unlockingScript = 'aabb';

    const { tx } = buildCallTransaction(utxo, unlockingScript);
    const parsed = parseTxHex(tx.toHex());

    // Input 0 should contain the unlocking script
    expect(parsed.inputs[0]!.script).toBe(unlockingScript);
    expect(parsed.inputs[0]!.script.length).toBeGreaterThan(0);
  });

  it('sets all input sequences to 0xffffffff (final, no RBF)', () => {
    const utxo = makeUtxo(100000);
    const additional = [makeUtxo(50000, 1), makeUtxo(30000, 2)];

    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      '76a914' + 'ff'.repeat(20) + '88ac',
      additional,
    );
    const parsed = parseTxHex(tx.toHex());

    for (const input of parsed.inputs) {
      expect(input.sequence).toBe(0xffffffff);
    }
  });

  it('encodes the contract UTXO txid in reversed byte order (Bitcoin wire format)', () => {
    const utxo = makeUtxo(100000);
    const { tx } = buildCallTransaction(utxo, '51');
    const parsed = parseTxHex(tx.toHex());

    // The prevTxid in the wire format should be the reverse of the UTXO txid
    expect(parsed.inputs[0]!.prevTxid).toBe(reverseHex(utxo.txid));
  });
});

// ---------------------------------------------------------------------------
// Input handling
// ---------------------------------------------------------------------------

describe('buildCallTransaction — inputs', () => {
  it('creates exactly 1 input for contract UTXO only (no additional UTXOs)', () => {
    const utxo = makeUtxo(100000);
    const { tx, inputCount } = buildCallTransaction(utxo, '51');
    const parsed = parseTxHex(tx.toHex());

    expect(inputCount).toBe(1);
    expect(parsed.inputCount).toBe(1);
    expect(parsed.inputs.length).toBe(1);
  });

  it('includes additional funding UTXOs as extra inputs with empty scriptSig', () => {
    const utxo = makeUtxo(100000);
    const additional = [makeUtxo(50000, 1), makeUtxo(30000, 2)];
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx, inputCount } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
      additional,
    );
    const parsed = parseTxHex(tx.toHex());

    expect(inputCount).toBe(3);
    expect(parsed.inputCount).toBe(3);

    // Input 0 has the unlocking script
    expect(parsed.inputs[0]!.script).toBe('51');

    // Additional inputs have empty scriptSig (varint '00' → 0 bytes → empty string)
    expect(parsed.inputs[1]!.script).toBe('');
    expect(parsed.inputs[2]!.script).toBe('');
  });

  it('references the correct output index from the contract UTXO', () => {
    const utxo = makeUtxo(100000, 3);
    const { tx } = buildCallTransaction(utxo, '51');
    const parsed = parseTxHex(tx.toHex());

    expect(parsed.inputs[0]!.prevIndex).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Output handling — stateful contracts
// ---------------------------------------------------------------------------

describe('buildCallTransaction — stateful outputs', () => {
  it('creates output 0 with newLockingScript and newSatoshis for stateful calls', () => {
    const utxo = makeUtxo(100000);
    const newLockingScript = '76a914' + 'dd'.repeat(20) + '88ac';
    const newSatoshis = 50000;
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '51',
      newLockingScript,
      newSatoshis,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // First output should be the contract continuation
    expect(parsed.outputs[0]!.script).toBe(newLockingScript);
    expect(parsed.outputs[0]!.satoshis).toBe(newSatoshis);
  });

  it('uses currentUtxo.satoshis as default when newSatoshis is undefined', () => {
    const utxo = makeUtxo(75000);
    const newLockingScript = '51';
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '00',
      newLockingScript,
      undefined,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // Output 0 satoshis should default to the input UTXO satoshis
    expect(parsed.outputs[0]!.satoshis).toBe(75000);
  });

  it('does NOT create contract output when newLockingScript is undefined (stateless)', () => {
    const utxo = makeUtxo(100000);
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // For stateless: only change output (no contract continuation output)
    // The change output script should be the change script
    if (parsed.outputCount > 0) {
      expect(parsed.outputs[0]!.script).toBe(changeScript);
    }
  });
});

// ---------------------------------------------------------------------------
// Change output and fee calculation
// ---------------------------------------------------------------------------

describe('buildCallTransaction — change and fees', () => {
  it('calculates change as totalInput - contractOutput - fee', () => {
    const utxo = makeUtxo(100000);
    const newLockingScript = '51';
    const newSatoshis = 50000;
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '00',
      newLockingScript,
      newSatoshis,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // Fee: input0(32+4+1+1+4=42) + contractOut(8+1+1=10) + changeOut(34) + overhead(10) = 96 bytes
    // At 100 sat/KB: fee = ceil(96 * 100 / 1000) = 10
    // Change = 100000 - 50000 - 10 = 49990
    expect(parsed.outputCount).toBe(2);
    expect(parsed.outputs[0]!.satoshis).toBe(50000);
    expect(parsed.outputs[1]!.satoshis).toBe(49990);
    expect(parsed.outputs[1]!.script).toBe(changeScript);
  });

  it('omits change output when change is zero', () => {
    // Fee: 96 bytes at 100 sat/KB = ceil(96 * 100 / 1000) = 10
    // To get change = 0: totalInput = contractOutput + fee
    // 50010 = 50000 + 10
    const utxo = makeUtxo(50010);
    const newLockingScript = '51';
    const newSatoshis = 50000;
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '00',
      newLockingScript,
      newSatoshis,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // Only the contract output, no change output
    expect(parsed.outputCount).toBe(1);
    expect(parsed.outputs[0]!.satoshis).toBe(50000);
  });

  it('omits change output when change is negative (all funds consumed by fee)', () => {
    // Fee: 96 bytes at 100 sat/KB = ceil(96 * 100 / 1000) = 10
    // Set up so totalInput - contractOutput < fee
    // 50005 - 50000 = 5 < 10 → change = -5, negative
    const utxo = makeUtxo(50005);
    const newLockingScript = '51';
    const newSatoshis = 50000;
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '00',
      newLockingScript,
      newSatoshis,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // No change output since change <= 0
    expect(parsed.outputCount).toBe(1);
  });

  it('accumulates satoshis from additional UTXOs in fee/change calculation', () => {
    const utxo = makeUtxo(50000);
    const additional = [makeUtxo(30000, 1)];
    const newLockingScript = '51';
    const newSatoshis = 40000;
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '00',
      newLockingScript,
      newSatoshis,
      'changeaddr',
      changeScript,
      additional,
    );
    const parsed = parseTxHex(tx.toHex());

    // Fee: input0(42) + additional(148) + contractOut(10) + changeOut(34) + overhead(10) = 244 bytes
    // At 100 sat/KB: fee = ceil(244 * 100 / 1000) = 25
    // Total input: 50000 + 30000 = 80000
    // Change: 80000 - 40000 - 25 = 39975
    expect(parsed.outputCount).toBe(2);
    expect(parsed.outputs[0]!.satoshis).toBe(40000);
    expect(parsed.outputs[1]!.satoshis).toBe(39975);
  });

  it('fee scales with input count', () => {
    const utxo = makeUtxo(200000);
    const threeAdditional = [makeUtxo(100000, 1), makeUtxo(100000, 2), makeUtxo(100000, 3)];
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx: tx1 } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
    );

    const { tx: tx4 } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
      threeAdditional,
    );

    const parsed1 = parseTxHex(tx1.toHex());
    const parsed4 = parseTxHex(tx4.toHex());

    // Both are stateless (no contract output), so just change output
    // 1 input: 86 bytes at 100 sat/KB → fee = ceil(8.6) = 9; change = 200000 - 9 = 199991
    // 4 inputs: 530 bytes at 100 sat/KB → fee = ceil(53) = 53; change = 500000 - 53 = 499947
    expect(parsed1.outputs[0]!.satoshis).toBe(199991);
    expect(parsed4.outputs[0]!.satoshis).toBe(499947);

    // More inputs → higher fee
    const fee1 = 200000 - parsed1.outputs[0]!.satoshis;
    const fee4 = 500000 - parsed4.outputs[0]!.satoshis;
    expect(fee4).toBeGreaterThan(fee1);
  });
});

// ---------------------------------------------------------------------------
// Stateless call (no new locking script)
// ---------------------------------------------------------------------------

describe('buildCallTransaction — stateless call', () => {
  it('produces only a change output when no newLockingScript is provided', () => {
    const utxo = makeUtxo(100000);
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // Fee: input0(42) + changeOut(34) + overhead(10) = 86 bytes
    // At 100 sat/KB: fee = ceil(86 * 100 / 1000) = 9
    // Change: 100000 - 0 - 9 = 99991
    expect(parsed.outputCount).toBe(1);
    expect(parsed.outputs[0]!.script).toBe(changeScript);
    expect(parsed.outputs[0]!.satoshis).toBe(99991);
  });

  it('produces no outputs when stateless and change is zero or negative', () => {
    // Fee: 86 bytes at 100 sat/KB = ceil(86 * 100 / 1000) = 9
    // To get exactly 0 change: satoshis = fee = 9
    const utxo = makeUtxo(9);
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      'changeaddr',
      changeScript,
    );
    const parsed = parseTxHex(tx.toHex());

    // Change = 192 - 0 - 192 = 0 → no change output
    expect(parsed.outputCount).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Fix #18: P2PKH address should use Base58Check decoding, not deterministicHash20
// ---------------------------------------------------------------------------

describe('buildCallTransaction — P2PKH address decoding', () => {
  it('builds correct P2PKH script from a Base58Check address', () => {
    // Use a well-known Bitcoin address to verify proper decoding.
    // Address 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 has hash160:
    // 77bff20c60e522dfaa3350c39b030a5d004e839a
    // (This is a standard mainnet P2PKH address)
    const knownAddress = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
    const expectedHash160 = '77bff20c60e522dfaa3350c39b030a5d004e839a';

    const utxo = makeUtxo(100000);
    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      knownAddress,
    );

    const parsed = parseTxHex(tx.toHex());

    // If there's a change output, check it contains the correct P2PKH script
    if (parsed.outputCount > 0) {
      const changeOutput = parsed.outputs[parsed.outputCount - 1]!;
      // P2PKH script: 76a914 + <20-byte hash> + 88ac
      const expectedScript = '76a914' + expectedHash160 + '88ac';
      expect(changeOutput.script).toBe(expectedScript);
    }
  });

  it('still accepts a raw 40-char hex hash directly', () => {
    const rawHash = 'aabbccdd'.repeat(5); // 40 hex chars = 20 bytes
    const utxo = makeUtxo(100000);
    const { tx } = buildCallTransaction(
      utxo,
      '51',
      undefined,
      undefined,
      rawHash,
    );
    const parsed = parseTxHex(tx.toHex());

    if (parsed.outputCount > 0) {
      const changeOutput = parsed.outputs[parsed.outputCount - 1]!;
      expect(changeOutput.script).toBe('76a914' + rawHash + '88ac');
    }
  });
});
