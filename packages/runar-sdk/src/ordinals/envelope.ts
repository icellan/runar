// ---------------------------------------------------------------------------
// runar-sdk/ordinals/envelope.ts — Build and parse 1sat ordinal inscriptions
// ---------------------------------------------------------------------------
//
// Envelope layout:
//   OP_FALSE OP_IF PUSH("ord") OP_1 PUSH(<content-type>) OP_0 PUSH(<data>) OP_ENDIF
//
// Hex:
//   00 63 03 6f7264 51 <push content-type> 00 <push data> 68
//
// The envelope is a no-op (OP_FALSE causes the IF block to be skipped)
// and can be placed anywhere in a script without affecting execution.
// ---------------------------------------------------------------------------

import type { Inscription, EnvelopeBounds } from './types.js';

// ---------------------------------------------------------------------------
// Push-data encoding (same logic as contract.ts / state.ts, kept local to
// avoid exporting private helpers from those modules)
// ---------------------------------------------------------------------------

function encodePushData(dataHex: string): string {
  if (dataHex.length === 0) return '00'; // OP_0
  const len = dataHex.length / 2;

  if (len <= 75) {
    return len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xff) {
    return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xffff) {
    const lo = (len & 0xff).toString(16).padStart(2, '0');
    const hi = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
    return '4d' + lo + hi + dataHex;
  }
  const b0 = (len & 0xff).toString(16).padStart(2, '0');
  const b1 = ((len >> 8) & 0xff).toString(16).padStart(2, '0');
  const b2 = ((len >> 16) & 0xff).toString(16).padStart(2, '0');
  const b3 = ((len >> 24) & 0xff).toString(16).padStart(2, '0');
  return '4e' + b0 + b1 + b2 + b3 + dataHex;
}

/** Convert a UTF-8 string to its hex representation. */
function utf8ToHex(str: string): string {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Convert a hex string to UTF-8. */
function hexToUtf8(hex: string): string {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/**
 * Build a 1sat ordinals inscription envelope as hex.
 *
 * @param contentType - MIME type (e.g. "image/png", "application/bsv-20")
 * @param data - Hex-encoded inscription content
 * @returns Hex string of the full envelope script fragment
 */
export function buildInscriptionEnvelope(
  contentType: string,
  data: string,
): string {
  const contentTypeHex = utf8ToHex(contentType);

  // OP_FALSE (00) OP_IF (63) PUSH "ord" (03 6f7264) OP_1 (51)
  let hex = '006303' + '6f7264' + '51';
  // PUSH content-type
  hex += encodePushData(contentTypeHex);
  // OP_0 (00) — content delimiter
  hex += '00';
  // PUSH data
  hex += encodePushData(data);
  // OP_ENDIF (68)
  hex += '68';

  return hex;
}

// ---------------------------------------------------------------------------
// Parse / Find
// ---------------------------------------------------------------------------

/**
 * Read a push-data value at the given hex offset. Returns the pushed data
 * (hex) and the total number of hex chars consumed (including the length
 * prefix).
 */
function readPushData(
  scriptHex: string,
  offset: number,
): { data: string; bytesRead: number } | null {
  if (offset + 2 > scriptHex.length) return null;
  const opcode = parseInt(scriptHex.slice(offset, offset + 2), 16);

  if (opcode >= 0x01 && opcode <= 0x4b) {
    const dataLen = opcode * 2;
    if (offset + 2 + dataLen > scriptHex.length) return null;
    return { data: scriptHex.slice(offset + 2, offset + 2 + dataLen), bytesRead: 2 + dataLen };
  } else if (opcode === 0x4c) {
    // OP_PUSHDATA1
    if (offset + 4 > scriptHex.length) return null;
    const len = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    const dataLen = len * 2;
    if (offset + 4 + dataLen > scriptHex.length) return null;
    return { data: scriptHex.slice(offset + 4, offset + 4 + dataLen), bytesRead: 4 + dataLen };
  } else if (opcode === 0x4d) {
    // OP_PUSHDATA2
    if (offset + 6 > scriptHex.length) return null;
    const lo = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    const hi = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
    const len = lo | (hi << 8);
    const dataLen = len * 2;
    if (offset + 6 + dataLen > scriptHex.length) return null;
    return { data: scriptHex.slice(offset + 6, offset + 6 + dataLen), bytesRead: 6 + dataLen };
  } else if (opcode === 0x4e) {
    // OP_PUSHDATA4
    if (offset + 10 > scriptHex.length) return null;
    const b0 = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    const b1 = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
    const b2 = parseInt(scriptHex.slice(offset + 6, offset + 8), 16);
    const b3 = parseInt(scriptHex.slice(offset + 8, offset + 10), 16);
    const len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    const dataLen = len * 2;
    if (offset + 10 + dataLen > scriptHex.length) return null;
    return { data: scriptHex.slice(offset + 10, offset + 10 + dataLen), bytesRead: 10 + dataLen };
  }

  return null;
}

/**
 * Compute the number of hex chars an opcode occupies (including its push
 * data) so we can advance past it while walking a script.
 */
function opcodeSize(scriptHex: string, offset: number): number {
  if (offset + 2 > scriptHex.length) return 2;
  const opcode = parseInt(scriptHex.slice(offset, offset + 2), 16);

  if (opcode >= 0x01 && opcode <= 0x4b) {
    return 2 + opcode * 2;
  } else if (opcode === 0x4c) {
    if (offset + 4 > scriptHex.length) return 2;
    const len = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    return 4 + len * 2;
  } else if (opcode === 0x4d) {
    if (offset + 6 > scriptHex.length) return 2;
    const lo = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    const hi = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
    return 6 + (lo | (hi << 8)) * 2;
  } else if (opcode === 0x4e) {
    if (offset + 10 > scriptHex.length) return 2;
    const b0 = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
    const b1 = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
    const b2 = parseInt(scriptHex.slice(offset + 6, offset + 8), 16);
    const b3 = parseInt(scriptHex.slice(offset + 8, offset + 10), 16);
    return 10 + (b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)) * 2;
  }

  return 2; // all other opcodes are 1 byte
}

/**
 * Find the inscription envelope within a script hex string.
 *
 * Walks the script as Bitcoin Script opcodes (identical in shape to
 * `findLastOpReturn` in state.ts) looking for the pattern:
 *   OP_FALSE(00) OP_IF(63) PUSH3 "ord"(03 6f7264) ...
 *
 * @returns Hex-char offsets of the envelope, or null if not found.
 */
export function findInscriptionEnvelope(scriptHex: string): EnvelopeBounds | null {
  let offset = 0;
  const len = scriptHex.length;

  while (offset + 2 <= len) {
    const opcode = parseInt(scriptHex.slice(offset, offset + 2), 16);

    // Look for OP_FALSE (0x00)
    if (opcode === 0x00) {
      // Check: OP_IF (63) PUSH3 (03) "ord" (6f7264)
      if (
        offset + 12 <= len &&
        scriptHex.slice(offset + 2, offset + 4) === '63' && // OP_IF
        scriptHex.slice(offset + 4, offset + 12) === '036f7264' // PUSH3 "ord"
      ) {
        const envelopeStart = offset;
        // Skip: OP_FALSE(2) + OP_IF(2) + PUSH3 "ord"(8) = 12 hex chars
        let pos = offset + 12;

        // Expect OP_1 (0x51)
        if (pos + 2 > len || scriptHex.slice(pos, pos + 2) !== '51') {
          offset += 2;
          continue;
        }
        pos += 2; // skip OP_1

        // Read content-type push
        const ctPush = readPushData(scriptHex, pos);
        if (!ctPush) { offset += 2; continue; }
        pos += ctPush.bytesRead;

        // Expect OP_0 (0x00) — content delimiter
        if (pos + 2 > len || scriptHex.slice(pos, pos + 2) !== '00') {
          offset += 2;
          continue;
        }
        pos += 2; // skip OP_0

        // Read data push
        const dataPush = readPushData(scriptHex, pos);
        if (!dataPush) { offset += 2; continue; }
        pos += dataPush.bytesRead;

        // Expect OP_ENDIF (0x68)
        if (pos + 2 > len || scriptHex.slice(pos, pos + 2) !== '68') {
          offset += 2;
          continue;
        }
        pos += 2; // skip OP_ENDIF

        return { startHex: envelopeStart, endHex: pos };
      }
    }

    // Advance past this opcode
    offset += opcodeSize(scriptHex, offset);
  }

  return null;
}

/**
 * Parse an inscription envelope from a script hex string.
 *
 * @returns The inscription data, or null if no envelope is found.
 */
export function parseInscriptionEnvelope(scriptHex: string): Inscription | null {
  const bounds = findInscriptionEnvelope(scriptHex);
  if (!bounds) return null;

  const envelopeHex = scriptHex.slice(bounds.startHex, bounds.endHex);

  // Parse the envelope contents:
  // 00 63 03 6f7264 51 <ct-push> 00 <data-push> 68
  let pos = 12; // skip OP_FALSE + OP_IF + PUSH3 "ord"
  pos += 2; // skip OP_1

  const ctPush = readPushData(envelopeHex, pos);
  if (!ctPush) return null;
  pos += ctPush.bytesRead;

  pos += 2; // skip OP_0

  const dataPush = readPushData(envelopeHex, pos);
  if (!dataPush) return null;

  return {
    contentType: hexToUtf8(ctPush.data),
    data: dataPush.data,
  };
}

/**
 * Remove the inscription envelope from a script, returning the bare script.
 *
 * @returns Script hex with the envelope removed, or the original if none found.
 */
export function stripInscriptionEnvelope(scriptHex: string): string {
  const bounds = findInscriptionEnvelope(scriptHex);
  if (!bounds) return scriptHex;
  return scriptHex.slice(0, bounds.startHex) + scriptHex.slice(bounds.endHex);
}
