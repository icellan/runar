// ---------------------------------------------------------------------------
// runar-sdk/calling.ts — Transaction construction for method invocation
// ---------------------------------------------------------------------------

import type { UTXO } from './types.js';

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
): { txHex: string; inputCount: number } {
  const allUtxos = [currentUtxo, ...(additionalUtxos ?? [])];

  const totalInput = allUtxos.reduce((sum, u) => sum + u.satoshis, 0);

  // Calculate outputs total
  const contractOutputSats = newLockingScript ? (newSatoshis ?? currentUtxo.satoshis) : 0;

  // Estimate fee
  const estimatedInputSize = allUtxos.length * 148;
  const outputCount =
    (newLockingScript ? 1 : 0) + (changeAddress || changeScript ? 1 : 0);
  const estimatedOutputSize = outputCount * 34;
  const estimatedSize = estimatedInputSize + estimatedOutputSize + 10;
  const fee = estimatedSize; // 1 sat/byte

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

function buildP2PKHScript(address: string): string {
  const pubKeyHash =
    /^[0-9a-fA-F]{40}$/.test(address) ? address : deterministicHash20(address);
  return '76a914' + pubKeyHash + '88ac';
}

function deterministicHash20(input: string): string {
  const bytes = new Uint8Array(20);
  for (let i = 0; i < input.length; i++) {
    bytes[i % 20] = ((bytes[i % 20]! ^ input.charCodeAt(i)) * 31 + 17) & 0xff;
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
