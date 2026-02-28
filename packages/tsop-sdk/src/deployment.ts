// ---------------------------------------------------------------------------
// tsop-sdk/deployment.ts — Transaction construction for contract deployment
// ---------------------------------------------------------------------------

import type { UTXO } from './types.js';
import { Utils } from '@bsv/sdk';

/**
 * Build a raw transaction that creates an output with the given locking
 * script. The transaction consumes the provided UTXOs, places the contract
 * output first, and sends any remaining value (minus fees) to a change
 * address.
 *
 * Returns the unsigned transaction hex and the number of inputs (needed so
 * the caller knows how many inputs to sign).
 */
export function buildDeployTransaction(
  lockingScript: string,
  utxos: UTXO[],
  satoshis: number,
  changeAddress: string,
  changeScript: string,
): { txHex: string; inputCount: number } {
  if (utxos.length === 0) {
    throw new Error('buildDeployTransaction: no UTXOs provided');
  }

  const totalInput = utxos.reduce((sum, u) => sum + u.satoshis, 0);
  // Estimate fee: ~148 bytes per input + ~34 bytes per output + 10 byte overhead
  const estimatedSize = utxos.length * 148 + 2 * 34 + 10;
  const feeRate = 1; // 1 sat/byte (BSV)
  const fee = estimatedSize * feeRate;
  const change = totalInput - satoshis - fee;

  if (change < 0) {
    throw new Error(
      `buildDeployTransaction: insufficient funds. Need ${satoshis + fee} sats, have ${totalInput}`,
    );
  }

  // Build raw transaction using Bitcoin wire format
  let tx = '';

  // Version (4 bytes LE)
  tx += toLittleEndian32(1);

  // Input count (varint)
  tx += encodeVarInt(utxos.length);

  // Inputs (unsigned — scriptSig is empty)
  for (const utxo of utxos) {
    // Previous txid (32 bytes, internal byte order = reversed hex)
    tx += reverseHex(utxo.txid);
    // Previous output index (4 bytes LE)
    tx += toLittleEndian32(utxo.outputIndex);
    // ScriptSig length + script (empty for unsigned)
    tx += '00';
    // Sequence (4 bytes LE) — 0xffffffff
    tx += 'ffffffff';
  }

  // Output count
  const hasChange = change > 0;
  const outputCount = hasChange ? 2 : 1;
  tx += encodeVarInt(outputCount);

  // Output 0: contract locking script
  tx += toLittleEndian64(satoshis);
  tx += encodeVarInt(lockingScript.length / 2);
  tx += lockingScript;

  // Output 1: change (if any)
  if (hasChange) {
    const actualChangeScript = changeScript || buildP2PKHScript(changeAddress);
    tx += toLittleEndian64(change);
    tx += encodeVarInt(actualChangeScript.length / 2);
    tx += actualChangeScript;
  }

  // Locktime (4 bytes LE)
  tx += toLittleEndian32(0);

  return { txHex: tx, inputCount: utxos.length };
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
  // For satoshi values that fit in a standard JS number (< 2^53)
  const lo = n & 0xffffffff;
  const hi = Math.floor(n / 0x100000000) & 0xffffffff;
  return toLittleEndian32(lo) + toLittleEndian32(hi);
}

function encodeVarInt(n: number): string {
  if (n < 0xfd) {
    return n.toString(16).padStart(2, '0');
  } else if (n <= 0xffff) {
    return 'fd' + toLittleEndian16(n);
  } else if (n <= 0xffffffff) {
    return 'fe' + toLittleEndian32(n);
  } else {
    return 'ff' + toLittleEndian64(n);
  }
}

function toLittleEndian16(n: number): string {
  const buf = new ArrayBuffer(2);
  new DataView(buf).setUint16(0, n, true);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function reverseHex(hex: string): string {
  const pairs: string[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    pairs.push(hex.slice(i, i + 2));
  }
  return pairs.reverse().join('');
}

/**
 * Build a standard P2PKH locking script from an address.
 *
 *   OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 *   76      a9         14        <20 bytes>    88              ac
 *
 * Accepts either a 40-char hex string (raw pubkey hash) or a Base58Check-
 * encoded BSV address which is decoded via @bsv/sdk.
 */
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

  // OP_DUP OP_HASH160 OP_PUSH20 <hash> OP_EQUALVERIFY OP_CHECKSIG
  return '76a914' + pubKeyHash + '88ac';
}
