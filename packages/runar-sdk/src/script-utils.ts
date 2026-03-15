// ---------------------------------------------------------------------------
// runar-sdk/script-utils.ts — Script utilities
// ---------------------------------------------------------------------------

import { Hash, Utils } from '@bsv/sdk';
import type { RunarArtifact } from 'runar-ir-schema';
import { findLastOpReturn } from './state.js';

/**
 * Build a standard P2PKH locking script hex from an address, pubkey hash,
 * or public key.
 *
 *   OP_DUP OP_HASH160 OP_PUSH20 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
 *   76      a9         14        <20 bytes>    88              ac
 *
 * Accepted input formats:
 * - 40-char hex: treated as raw 20-byte pubkey hash (hash160)
 * - 66-char hex: compressed public key (auto-hashed via hash160)
 * - 130-char hex: uncompressed public key (auto-hashed via hash160)
 * - Other: decoded as Base58Check BSV address
 */
export function buildP2PKHScript(addressOrPubKey: string): string {
  let pubKeyHash: string;

  if (/^[0-9a-fA-F]{40}$/.test(addressOrPubKey)) {
    // Already a raw 20-byte pubkey hash in hex
    pubKeyHash = addressOrPubKey;
  } else if (/^[0-9a-fA-F]{66}$/.test(addressOrPubKey) || /^[0-9a-fA-F]{130}$/.test(addressOrPubKey)) {
    // Compressed (33 bytes) or uncompressed (65 bytes) public key — hash it
    const pubKeyBytes = Utils.toArray(addressOrPubKey, 'hex');
    const hash160Bytes = Hash.hash160(pubKeyBytes);
    pubKeyHash = Utils.toHex(hash160Bytes);
  } else {
    // Decode Base58Check address to extract the 20-byte pubkey hash
    const decoded = Utils.fromBase58Check(addressOrPubKey);
    pubKeyHash = typeof decoded.data === 'string'
      ? decoded.data
      : Utils.toHex(decoded.data);
  }

  return '76a914' + pubKeyHash + '88ac';
}

// ---------------------------------------------------------------------------
// Constructor arg extraction
// ---------------------------------------------------------------------------

function readScriptElement(
  hex: string,
  offset: number,
): { dataHex: string; totalHexChars: number; opcode: number } {
  const opcode = parseInt(hex.slice(offset, offset + 2), 16);

  if (opcode === 0x00) return { dataHex: '', totalHexChars: 2, opcode };
  if (opcode >= 0x01 && opcode <= 0x4b) {
    const dataLen = opcode * 2;
    return { dataHex: hex.slice(offset + 2, offset + 2 + dataLen), totalHexChars: 2 + dataLen, opcode };
  }
  if (opcode === 0x4c) {
    const len = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const dataLen = len * 2;
    return { dataHex: hex.slice(offset + 4, offset + 4 + dataLen), totalHexChars: 4 + dataLen, opcode };
  }
  if (opcode === 0x4d) {
    const lo = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const hi = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const len = lo | (hi << 8);
    const dataLen = len * 2;
    return { dataHex: hex.slice(offset + 6, offset + 6 + dataLen), totalHexChars: 6 + dataLen, opcode };
  }
  if (opcode === 0x4e) {
    const b0 = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const b1 = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const b2 = parseInt(hex.slice(offset + 6, offset + 8), 16);
    const b3 = parseInt(hex.slice(offset + 8, offset + 10), 16);
    const len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    const dataLen = len * 2;
    return { dataHex: hex.slice(offset + 10, offset + 10 + dataLen), totalHexChars: 10 + dataLen, opcode };
  }
  return { dataHex: '', totalHexChars: 2, opcode };
}

function decodeScriptNumber(dataHex: string): bigint {
  if (dataHex.length === 0) return 0n;
  const bytes: number[] = [];
  for (let i = 0; i < dataHex.length; i += 2) bytes.push(parseInt(dataHex.slice(i, i + 2), 16));
  const negative = (bytes[bytes.length - 1]! & 0x80) !== 0;
  bytes[bytes.length - 1]! &= 0x7f;
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i]!);
  if (result === 0n) return 0n;
  return negative ? -result : result;
}

function interpretScriptElement(opcode: number, dataHex: string, type: string): unknown {
  switch (type) {
    case 'int':
    case 'bigint': {
      if (opcode === 0x00) return 0n;
      if (opcode >= 0x51 && opcode <= 0x60) return BigInt(opcode - 0x50);
      if (opcode === 0x4f) return -1n;
      return decodeScriptNumber(dataHex);
    }
    case 'bool': {
      if (opcode === 0x00) return false;
      if (opcode === 0x51) return true;
      return dataHex !== '00';
    }
    default:
      return dataHex;
  }
}

/**
 * Extract constructor argument values from a compiled on-chain script.
 *
 * Uses `artifact.constructorSlots` to locate each constructor arg at its
 * byte offset, reads the push data, and deserializes according to the
 * ABI param type.
 */
export function extractConstructorArgs(
  artifact: RunarArtifact,
  scriptHex: string,
): Record<string, unknown> {
  if (!artifact.constructorSlots || artifact.constructorSlots.length === 0) return {};

  let codeHex = scriptHex;
  if (artifact.stateFields && artifact.stateFields.length > 0) {
    const opReturnPos = findLastOpReturn(scriptHex);
    if (opReturnPos !== -1) codeHex = scriptHex.slice(0, opReturnPos);
  }

  const seen = new Set<number>();
  const slots = [...artifact.constructorSlots]
    .sort((a, b) => a.byteOffset - b.byteOffset)
    .filter((slot) => { if (seen.has(slot.paramIndex)) return false; seen.add(slot.paramIndex); return true; });

  const result: Record<string, unknown> = {};
  let cumulativeShift = 0;

  for (const slot of slots) {
    const adjustedHexOffset = (slot.byteOffset + cumulativeShift) * 2;
    const elem = readScriptElement(codeHex, adjustedHexOffset);
    cumulativeShift += elem.totalHexChars / 2 - 1;
    const param = artifact.abi.constructor.params[slot.paramIndex];
    if (!param) continue;
    result[param.name] = interpretScriptElement(elem.opcode, elem.dataHex, param.type);
  }

  return result;
}

// ---------------------------------------------------------------------------
// Script matching
// ---------------------------------------------------------------------------

/**
 * Determine whether a given on-chain script was produced from the given
 * contract artifact (regardless of what constructor args were used).
 */
export function matchesArtifact(
  artifact: RunarArtifact,
  scriptHex: string,
): boolean {
  let codeHex = scriptHex;
  if (artifact.stateFields && artifact.stateFields.length > 0) {
    const opReturnPos = findLastOpReturn(scriptHex);
    if (opReturnPos !== -1) codeHex = scriptHex.slice(0, opReturnPos);
  }

  const template = artifact.script;

  if (!artifact.constructorSlots || artifact.constructorSlots.length === 0) return codeHex === template;

  const seenOffsets = new Set<number>();
  const slots = [...artifact.constructorSlots]
    .sort((a, b) => a.byteOffset - b.byteOffset)
    .filter((slot) => { if (seenOffsets.has(slot.byteOffset)) return false; seenOffsets.add(slot.byteOffset); return true; });

  let templatePos = 0;
  let codePos = 0;

  for (const slot of slots) {
    const slotHexOffset = slot.byteOffset * 2;
    const templateSegment = template.slice(templatePos, slotHexOffset);
    const codeSegment = codeHex.slice(codePos, codePos + templateSegment.length);
    if (templateSegment !== codeSegment) return false;
    templatePos = slotHexOffset + 2;
    const elemOffset = codePos + templateSegment.length;
    const elem = readScriptElement(codeHex, elemOffset);
    codePos = elemOffset + elem.totalHexChars;
  }

  return template.slice(templatePos) === codeHex.slice(codePos);
}
