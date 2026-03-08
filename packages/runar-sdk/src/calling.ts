// ---------------------------------------------------------------------------
// runar-sdk/calling.ts — Transaction construction for method invocation
// ---------------------------------------------------------------------------

import type { UTXO } from './types.js';
import { Utils } from '@bsv/sdk';

/**
 * Build a raw transaction that spends a contract UTXO (method call).
 *
 * The transaction:
 * - Input 0: the current contract UTXO with the given unlocking script.
 * - Additional inputs: funding UTXOs if provided.
 * - Output 0 (optional): new contract UTXO with updated locking script
 *   (for stateful contracts).
 * - Last output (optional): change.
 *
 * Returns the unsigned transaction hex (with unlocking script for input 0
 * already placed) and the total input count.
 */
export function buildCallTransaction(
  currentUtxo: UTXO,
  unlockingScript: string,
  newLockingScript?: string,
  newSatoshis?: number,
  changeAddress?: string,
  changeScript?: string,
  additionalUtxos?: UTXO[],
  feeRate: number = 1,
  options?: {
    /** Multiple contract outputs (replaces single newLockingScript). */
    contractOutputs?: Array<{ script: string; satoshis: number }>;
    /** Additional contract inputs with their own unlocking scripts (for merge). */
    additionalContractInputs?: Array<{ utxo: UTXO; unlockingScript: string }>;
  },
): { txHex: string; inputCount: number; changeAmount: number } {
  const extraContractInputs = options?.additionalContractInputs ?? [];
  const allUtxos = [currentUtxo, ...extraContractInputs.map((i) => i.utxo), ...(additionalUtxos ?? [])];

  const totalInput = allUtxos.reduce((sum, u) => sum + u.satoshis, 0);

  // Determine contract outputs: multi-output takes priority over single
  const contractOutputs: Array<{ script: string; satoshis: number }> =
    options?.contractOutputs ??
    (newLockingScript
      ? [{ script: newLockingScript, satoshis: newSatoshis ?? currentUtxo.satoshis }]
      : []);

  const contractOutputSats = contractOutputs.reduce((sum, o) => sum + o.satoshis, 0);

  // Estimate fee using actual script sizes
  const input0Size = 32 + 4 + varIntByteSize(unlockingScript.length / 2) +
    unlockingScript.length / 2 + 4;
  let extraContractInputsSize = 0;
  for (const ci of extraContractInputs) {
    extraContractInputsSize += 32 + 4 +
      varIntByteSize(ci.unlockingScript.length / 2) +
      ci.unlockingScript.length / 2 + 4;
  }
  const p2pkhInputsSize = (additionalUtxos?.length ?? 0) * 148;
  const inputsSize = input0Size + extraContractInputsSize + p2pkhInputsSize;

  let outputsSize = 0;
  for (const co of contractOutputs) {
    outputsSize += 8 + varIntByteSize(co.script.length / 2) + co.script.length / 2;
  }
  if (changeAddress || changeScript) {
    outputsSize += 34; // P2PKH change
  }
  const estimatedSize = 10 + inputsSize + outputsSize;
  const fee = estimatedSize * feeRate;

  const change = totalInput - contractOutputSats - fee;

  // Build raw transaction
  let tx = '';

  // Version (4 bytes LE)
  tx += toLittleEndian32(1);

  // Input count
  tx += encodeVarInt(allUtxos.length);

  // Input 0: primary contract UTXO with unlocking script
  tx += reverseHex(currentUtxo.txid);
  tx += toLittleEndian32(currentUtxo.outputIndex);
  tx += encodeVarInt(unlockingScript.length / 2);
  tx += unlockingScript;
  tx += 'ffffffff';

  // Additional contract inputs (with their own unlocking scripts)
  for (const ci of extraContractInputs) {
    tx += reverseHex(ci.utxo.txid);
    tx += toLittleEndian32(ci.utxo.outputIndex);
    tx += encodeVarInt(ci.unlockingScript.length / 2);
    tx += ci.unlockingScript;
    tx += 'ffffffff';
  }

  // P2PKH funding inputs (unsigned)
  if (additionalUtxos) {
    for (const utxo of additionalUtxos) {
      tx += reverseHex(utxo.txid);
      tx += toLittleEndian32(utxo.outputIndex);
      tx += '00'; // empty scriptSig
      tx += 'ffffffff';
    }
  }

  // Output count
  let numOutputs = contractOutputs.length;
  if (change > 0 && (changeAddress || changeScript)) numOutputs++;
  tx += encodeVarInt(numOutputs);

  // Contract outputs
  for (const co of contractOutputs) {
    tx += toLittleEndian64(co.satoshis);
    tx += encodeVarInt(co.script.length / 2);
    tx += co.script;
  }

  // Change output
  if (change > 0 && (changeAddress || changeScript)) {
    const actualChangeScript =
      changeScript || buildP2PKHScript(changeAddress!);
    tx += toLittleEndian64(change);
    tx += encodeVarInt(actualChangeScript.length / 2);
    tx += actualChangeScript;
  }

  // Locktime
  tx += toLittleEndian32(0);

  return { txHex: tx, inputCount: allUtxos.length, changeAmount: change > 0 ? change : 0 };
}

// ---------------------------------------------------------------------------
// Bitcoin wire format helpers
// ---------------------------------------------------------------------------

function toLittleEndian32(n: number): string {
  const buf = new ArrayBuffer(4);
  new DataView(buf).setUint32(0, n, true);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function toLittleEndian64(n: number): string {
  const lo = n & 0xffffffff;
  const hi = Math.floor(n / 0x100000000) & 0xffffffff;
  return toLittleEndian32(lo) + toLittleEndian32(hi);
}

function encodeVarInt(n: number): string {
  if (n < 0xfd) {
    return n.toString(16).padStart(2, '0');
  } else if (n <= 0xffff) {
    const buf = new ArrayBuffer(2);
    new DataView(buf).setUint16(0, n, true);
    const hex = Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return 'fd' + hex;
  } else if (n <= 0xffffffff) {
    return 'fe' + toLittleEndian32(n);
  } else {
    return 'ff' + toLittleEndian64(n);
  }
}

function reverseHex(hex: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    pairs.push(hex.slice(i, i + 2));
  }
  return pairs.reverse().join('');
}

function varIntByteSize(n: number): number {
  if (n < 0xfd) return 1;
  if (n <= 0xffff) return 3;
  if (n <= 0xffffffff) return 5;
  return 9;
}

function buildP2PKHScript(address: string): string {
  let pubKeyHash: string;

  if (/^[0-9a-fA-F]{40}$/.test(address)) {
    // Already a raw 20-byte pubkey hash in hex
    pubKeyHash = address;
  } else {
    // Decode Base58Check address to extract the 20-byte pubkey hash
    const decoded = Utils.fromBase58Check(address);
    pubKeyHash = typeof decoded.data === 'string'
      ? decoded.data
      : Utils.toHex(decoded.data);
  }

  return '76a914' + pubKeyHash + '88ac';
}
