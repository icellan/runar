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
): { txHex: string; inputCount: number } {
  const allUtxos = [currentUtxo, ...(additionalUtxos ?? [])];

  const totalInput = allUtxos.reduce((sum, u) => sum + u.satoshis, 0);

  // Calculate outputs total
  const contractOutputSats = newLockingScript ? (newSatoshis ?? currentUtxo.satoshis) : 0;

  // Estimate fee using actual script sizes
  // Input 0 is the contract UTXO with a known unlocking script
  const input0Size = 32 + 4 + varIntByteSize(unlockingScript.length / 2) +
    unlockingScript.length / 2 + 4;
  const additionalInputsSize = (allUtxos.length - 1) * 148; // P2PKH
  const inputsSize = input0Size + additionalInputsSize;

  let outputsSize = 0;
  if (newLockingScript) {
    outputsSize += 8 + varIntByteSize(newLockingScript.length / 2) +
      newLockingScript.length / 2;
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

  // Input 0: contract UTXO with unlocking script
  tx += reverseHex(currentUtxo.txid);
  tx += toLittleEndian32(currentUtxo.outputIndex);
  tx += encodeVarInt(unlockingScript.length / 2);
  tx += unlockingScript;
  tx += 'ffffffff';

  // Additional inputs (unsigned)
  for (let i = 1; i < allUtxos.length; i++) {
    const utxo = allUtxos[i]!;
    tx += reverseHex(utxo.txid);
    tx += toLittleEndian32(utxo.outputIndex);
    tx += '00'; // empty scriptSig
    tx += 'ffffffff';
  }

  // Output count
  let numOutputs = 0;
  if (newLockingScript) numOutputs++;
  if (change > 0 && (changeAddress || changeScript)) numOutputs++;
  tx += encodeVarInt(numOutputs);

  // Output 0: new contract state (if stateful)
  if (newLockingScript) {
    tx += toLittleEndian64(contractOutputSats);
    tx += encodeVarInt(newLockingScript.length / 2);
    tx += newLockingScript;
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

  return { txHex: tx, inputCount: allUtxos.length };
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
