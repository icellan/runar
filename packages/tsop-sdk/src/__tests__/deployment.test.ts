import { describe, it, expect } from 'vitest';
import { buildDeployTransaction } from '../deployment.js';
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
 * This is a minimal parser for verification purposes.
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

  function readVarInt(): number {
    const first = parseInt(readBytes(1), 16);
    if (first < 0xfd) return first;
    if (first === 0xfd) {
      const h = readBytes(2);
      const lo = parseInt(h.slice(0, 2), 16);
      const hi = parseInt(h.slice(2, 4), 16);
      return lo | (hi << 8);
    }
    // 0xfe and 0xff: not needed for these tests
    throw new Error('Unsupported varint');
  }

  // Version
  const version = readUint32LE();

  // Input count
  const inputCount = readVarInt();

  // Inputs
  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxid = readBytes(32); // 32 bytes reversed
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
    const satoshisHex = readBytes(8); // 8 bytes LE
    const scriptLen = readVarInt();
    const script = readBytes(scriptLen);
    outputs.push({ satoshisHex, script });
  }

  // Locktime
  const locktime = readUint32LE();

  return { version, inputCount, inputs, outputCount, outputs, locktime };
}

// ---------------------------------------------------------------------------
// buildDeployTransaction produces valid hex
// ---------------------------------------------------------------------------

describe('buildDeployTransaction', () => {
  it('produces a non-empty hex string', () => {
    const lockingScript = '76a914' + '00'.repeat(20) + '88ac'; // P2PKH
    const utxos = [makeUtxo(100000)];
    const { txHex, inputCount } = buildDeployTransaction(
      lockingScript,
      utxos,
      50000,
      'testChangeAddress',
      '76a914' + 'ff'.repeat(20) + '88ac',
    );

    expect(txHex).toBeDefined();
    expect(txHex.length).toBeGreaterThan(0);
    expect(inputCount).toBe(1);
    // All hex chars
    expect(/^[0-9a-f]+$/.test(txHex)).toBe(true);
  });

  it('has correct transaction structure', () => {
    const lockingScript = '51'; // OP_1
    const utxos = [makeUtxo(100000)];
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { txHex } = buildDeployTransaction(
      lockingScript,
      utxos,
      50000,
      'testChangeAddress',
      changeScript,
    );

    const parsed = parseTxHex(txHex);

    // Version 1
    expect(parsed.version).toBe(1);

    // 1 input
    expect(parsed.inputCount).toBe(1);
    expect(parsed.inputs.length).toBe(1);

    // Input has empty scriptSig (unsigned)
    expect(parsed.inputs[0]!.script).toBe('');

    // Input sequence is 0xffffffff
    expect(parsed.inputs[0]!.sequence).toBe(0xffffffff);

    // 2 outputs (contract + change)
    expect(parsed.outputCount).toBe(2);
    expect(parsed.outputs.length).toBe(2);

    // First output is the contract locking script
    expect(parsed.outputs[0]!.script).toBe(lockingScript);

    // Second output is the change script
    expect(parsed.outputs[1]!.script).toBe(changeScript);

    // Locktime is 0
    expect(parsed.locktime).toBe(0);
  });

  it('handles multiple UTXOs', () => {
    const lockingScript = '51';
    const utxos = [makeUtxo(30000, 0), makeUtxo(40000, 1), makeUtxo(50000, 2)];
    const changeScript = '76a914' + 'ff'.repeat(20) + '88ac';

    const { txHex, inputCount } = buildDeployTransaction(
      lockingScript,
      utxos,
      50000,
      'testChangeAddress',
      changeScript,
    );

    expect(inputCount).toBe(3);

    const parsed = parseTxHex(txHex);
    expect(parsed.inputCount).toBe(3);
    expect(parsed.inputs.length).toBe(3);
  });

  it('throws if no UTXOs are provided', () => {
    expect(() =>
      buildDeployTransaction('51', [], 50000, 'addr', '51'),
    ).toThrow('no UTXOs provided');
  });

  it('throws if insufficient funds', () => {
    const utxos = [makeUtxo(100)]; // only 100 sats
    expect(() =>
      buildDeployTransaction('51', utxos, 50000, 'addr', '51'),
    ).toThrow('insufficient funds');
  });

  it('produces single output when change is zero', () => {
    // Construct such that totalInput - satoshis - fee = 0
    // fee = numInputs * 148 + 2 * 34 + 10 = 148 + 68 + 10 = 226
    // So totalInput = satoshis + fee = 50000 + 226 = 50226
    const utxos = [makeUtxo(50226)];
    const { txHex } = buildDeployTransaction(
      '51',
      utxos,
      50000,
      'addr',
      '51',
    );

    const parsed = parseTxHex(txHex);
    expect(parsed.outputCount).toBe(1);
  });
});
