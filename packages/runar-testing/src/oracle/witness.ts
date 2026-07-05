/**
 * Build a Bitcoin Script unlocking script (witness) from primitive args.
 * Mirrors the Go integration helper's buildUnlockingScript: bigints become
 * minimal script-number pushes, booleans OP_TRUE/OP_FALSE, bytes a
 * length-prefixed data push. Args are concatenated in method-argument order.
 */
import { encodeScriptNumber } from '../vm/index.js';

export type WitnessArg = bigint | boolean | Uint8Array;

const OP_TRUE = 0x51;
const OP_FALSE = 0x00;

function pushData(data: Uint8Array): Uint8Array {
  if (data.length === 0) return new Uint8Array([OP_FALSE]);
  if (data.length < 0x4c) {
    const out = new Uint8Array(1 + data.length);
    out[0] = data.length;
    out.set(data, 1);
    return out;
  }
  // PUSHDATA1 for 76..255 byte elements (sufficient for test witnesses).
  if (data.length <= 0xff) {
    const out = new Uint8Array(2 + data.length);
    out[0] = 0x4c;
    out[1] = data.length;
    out.set(data, 2);
    return out;
  }
  // PUSHDATA2 for larger elements.
  const out = new Uint8Array(3 + data.length);
  out[0] = 0x4d;
  out[1] = data.length & 0xff;
  out[2] = (data.length >> 8) & 0xff;
  out.set(data, 3);
  return out;
}

function encodeArg(arg: WitnessArg): Uint8Array {
  if (typeof arg === 'boolean') return new Uint8Array([arg ? OP_TRUE : OP_FALSE]);
  if (typeof arg === 'bigint') {
    const num = encodeScriptNumber(arg); // minimal little-endian sign-magnitude
    return pushData(num);
  }
  return pushData(arg);
}

export function buildWitness(args: WitnessArg[]): Uint8Array {
  const parts = args.map(encodeArg);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
