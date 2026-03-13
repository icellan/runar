// ---------------------------------------------------------------------------
// runar-sdk/state.ts -- State management for stateful contracts
// ---------------------------------------------------------------------------
//
// Stateful Runar contracts embed their state in the locking script as a
// suffix of OP_RETURN-delimited data pushes. The state section follows
// the contract's compiled code and is structured as:
//
//   <code> OP_RETURN <field0> <field1> ... <fieldN>
//
// Each field is encoded as a Bitcoin Script push according to its type.
// ---------------------------------------------------------------------------

import type { StateField, RunarArtifact } from 'runar-ir-schema';

/**
 * Serialize a set of state values into a hex-encoded Bitcoin Script data
 * section (without the OP_RETURN prefix -- that is handled by the caller).
 *
 * Field order is determined by the `index` property of each StateField.
 */
export function serializeState(
  fields: StateField[],
  values: Record<string, unknown>,
): string {
  const sorted = [...fields].sort((a, b) => a.index - b.index);
  let hex = '';

  for (const field of sorted) {
    const value = values[field.name];
    hex += encodeStateValue(value, field.type);
  }

  return hex;
}

/**
 * Deserialize state values from a hex-encoded Bitcoin Script data section.
 *
 * The caller must strip the code prefix and OP_RETURN byte before passing
 * the data section.
 */
export function deserializeState(
  fields: StateField[],
  scriptHex: string,
): Record<string, unknown> {
  const sorted = [...fields].sort((a, b) => a.index - b.index);
  const result: Record<string, unknown> = {};
  let offset = 0;

  for (const field of sorted) {
    const { value, bytesRead } = decodeStateValue(scriptHex, offset, field.type, field.name);
    result[field.name] = value;
    offset += bytesRead;
  }

  return result;
}

/**
 * Extract state from a full locking script hex, given the artifact.
 *
 * Returns null if the artifact has no state fields or the script doesn't
 * contain a recognisable state section.
 */
export function extractStateFromScript(
  artifact: RunarArtifact,
  scriptHex: string,
): Record<string, unknown> | null {
  if (!artifact.stateFields || artifact.stateFields.length === 0) {
    return null;
  }

  const opReturnPos = findLastOpReturn(scriptHex);
  if (opReturnPos === -1) {
    return null;
  }

  // State data starts after the OP_RETURN byte (2 hex chars)
  const stateHex = scriptHex.slice(opReturnPos + 2);
  return deserializeState(artifact.stateFields, stateHex);
}

/**
 * Walk the script hex as Bitcoin Script opcodes to find the last OP_RETURN
 * (0x6a) at a real opcode boundary. Unlike `lastIndexOf('6a')`, this
 * properly skips push data so it won't match 0x6a bytes inside data payloads.
 *
 * Returns the hex-char offset of the last OP_RETURN, or -1 if not found.
 */
export function findLastOpReturn(scriptHex: string): number {
  let offset = 0;
  const len = scriptHex.length;

  while (offset + 2 <= len) {
    const opcode = parseInt(scriptHex.slice(offset, offset + 2), 16);

    if (opcode === 0x6a) {
      // OP_RETURN at a real opcode boundary. Everything after OP_RETURN is
      // raw state data (not opcodes), so stop walking immediately.
      return offset;
    } else if (opcode >= 0x01 && opcode <= 0x4b) {
      // Direct push: opcode is the number of bytes to push
      offset += 2 + opcode * 2;
    } else if (opcode === 0x4c) {
      // OP_PUSHDATA1: next 1 byte is the length
      if (offset + 4 > len) break;
      const pushLen = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
      offset += 4 + pushLen * 2;
    } else if (opcode === 0x4d) {
      // OP_PUSHDATA2: next 2 bytes (LE) are the length
      if (offset + 6 > len) break;
      const lo = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
      const hi = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
      const pushLen = lo | (hi << 8);
      offset += 6 + pushLen * 2;
    } else if (opcode === 0x4e) {
      // OP_PUSHDATA4: next 4 bytes (LE) are the length
      if (offset + 10 > len) break;
      const b0 = parseInt(scriptHex.slice(offset + 2, offset + 4), 16);
      const b1 = parseInt(scriptHex.slice(offset + 4, offset + 6), 16);
      const b2 = parseInt(scriptHex.slice(offset + 6, offset + 8), 16);
      const b3 = parseInt(scriptHex.slice(offset + 8, offset + 10), 16);
      const pushLen = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
      offset += 10 + pushLen * 2;
    } else {
      // All other opcodes (OP_0, OP_1..OP_16, OP_IF, OP_ADD, etc.)
      offset += 2;
    }
  }

  return -1;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/**
 * Encode a state field as raw bytes (no push opcode wrapper) matching the
 * compiler's OP_NUM2BIN-based fixed-width serialization.
 * The result is raw hex bytes that are concatenated after OP_RETURN.
 */
function encodeStateValue(value: unknown, type: string): string {
  switch (type) {
    case 'int':
    case 'bigint': {
      let n: bigint;
      if (typeof value === 'bigint') {
        n = value;
      } else if (typeof value === 'string' && value.endsWith('n')) {
        // BigInt string from JSON without reviver (e.g. "0n", "1000n")
        n = BigInt(value.slice(0, -1));
      } else {
        n = BigInt(value as number);
      }
      return encodeNum2Bin(n, 8);
    }
    case 'bool': {
      return value ? '01' : '00'; // 1 raw byte
    }
    case 'PubKey':
    case 'Addr':
    case 'Ripemd160':
    case 'Sha256':
    case 'Point':
    case 'ByteString':
      // Fixed-size byte types: raw hex, no framing needed.
      // ByteString state fields (e.g., inductive internal outpoint fields) must use raw
      // bytes to match the compiler's OP_CAT-based continuation output serialization.
      return String(value);
    default: {
      // Variable-length types: use push-data encoding so the decoder can
      // determine the length.
      const hex = String(value);
      if (hex.length === 0) return '00'; // OP_0
      return encodePushDataState(hex);
    }
  }
}

/**
 * Encode an integer as a fixed-width LE sign-magnitude byte string,
 * matching OP_NUM2BIN behaviour. The sign bit is in the MSB of the last byte.
 */
function encodeNum2Bin(n: bigint, width: number): string {
  const bytes = new Uint8Array(width);
  const negative = n < 0n;
  let absVal = negative ? -n : n;

  for (let i = 0; i < width && absVal > 0n; i++) {
    bytes[i] = Number(absVal & 0xffn);
    absVal >>= 8n;
  }

  if (negative) {
    bytes[width - 1]! |= 0x80;
  }

  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Encode variable-length data as Bitcoin Script push data (with length prefix).
 */
function encodePushDataState(dataHex: string): string {
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

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

function decodeStateValue(
  hex: string,
  offset: number,
  type: string,
  name?: string,
): { value: unknown; bytesRead: number } {
  switch (type) {
    case 'bool': {
      // 1 raw byte: 0x00 = false, 0x01 = true
      return { value: hex.slice(offset, offset + 2) !== '00', bytesRead: 2 };
    }
    case 'int':
    case 'bigint': {
      // 8 raw bytes LE sign-magnitude (NUM2BIN 8)
      const hexWidth = 16; // 8 bytes * 2
      const data = hex.slice(offset, offset + hexWidth);
      return { value: decodeNum2Bin(data), bytesRead: hexWidth };
    }
    case 'PubKey':
      return { value: hex.slice(offset, offset + 66), bytesRead: 66 }; // 33 bytes
    case 'Addr':
    case 'Ripemd160':
      return { value: hex.slice(offset, offset + 40), bytesRead: 40 }; // 20 bytes
    case 'Sha256':
      return { value: hex.slice(offset, offset + 64), bytesRead: 64 }; // 32 bytes
    case 'Point':
      return { value: hex.slice(offset, offset + 128), bytesRead: 128 }; // 64 bytes
    case 'ByteString':
      // Inductive internal fields: raw hex without push-data encoding.
      // Size determined by field name.
      if (name === '_genesisOutpoint') {
        return { value: hex.slice(offset, offset + 72), bytesRead: 72 }; // 36 bytes
      } else if (name === '_proof') {
        return { value: hex.slice(offset, offset + 384), bytesRead: 384 }; // 192 bytes
      } else {
        // Unknown ByteString — try push-data decoding
        const { data, bytesRead } = decodePushData(hex, offset);
        return { value: data, bytesRead };
      }
    default: {
      // For unknown types, fall back to push-data decoding
      const { data, bytesRead } = decodePushData(hex, offset);
      return { value: data, bytesRead };
    }
  }
}

/**
 * Decode a fixed-width LE sign-magnitude number.
 */
function decodeNum2Bin(hex: string): bigint {
  if (hex.length === 0) return 0n;
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }

  const negative = (bytes[bytes.length - 1]! & 0x80) !== 0;
  bytes[bytes.length - 1]! &= 0x7f;

  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]!);
  }

  if (result === 0n) return 0n;
  return negative ? -result : result;
}

/**
 * Decode a Bitcoin Script push data at the given hex offset.
 * Returns the pushed data (hex) and the total number of hex chars consumed.
 */
function decodePushData(
  hex: string,
  offset: number,
): { data: string; bytesRead: number } {
  const opcode = parseInt(hex.slice(offset, offset + 2), 16);

  if (opcode <= 75) {
    // Direct push: opcode is the byte length
    const dataLen = opcode * 2;
    return {
      data: hex.slice(offset + 2, offset + 2 + dataLen),
      bytesRead: 2 + dataLen,
    };
  } else if (opcode === 0x4c) {
    // OP_PUSHDATA1
    const len = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const dataLen = len * 2;
    return {
      data: hex.slice(offset + 4, offset + 4 + dataLen),
      bytesRead: 4 + dataLen,
    };
  } else if (opcode === 0x4d) {
    // OP_PUSHDATA2
    const lo = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const hi = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const len = lo | (hi << 8);
    const dataLen = len * 2;
    return {
      data: hex.slice(offset + 6, offset + 6 + dataLen),
      bytesRead: 6 + dataLen,
    };
  } else if (opcode === 0x4e) {
    // OP_PUSHDATA4
    const b0 = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const b1 = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const b2 = parseInt(hex.slice(offset + 6, offset + 8), 16);
    const b3 = parseInt(hex.slice(offset + 8, offset + 10), 16);
    const len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    const dataLen = len * 2;
    return {
      data: hex.slice(offset + 10, offset + 10 + dataLen),
      bytesRead: 10 + dataLen,
    };
  }

  // Unknown opcode -- treat as zero-length
  return { data: '', bytesRead: 2 };
}

