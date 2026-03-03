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
    const { value, bytesRead } = decodeStateValue(scriptHex, offset, field.type);
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
  let lastPos = -1;
  let offset = 0;
  const len = scriptHex.length;

  while (offset + 2 <= len) {
    const opcode = parseInt(scriptHex.slice(offset, offset + 2), 16);

    if (opcode === 0x6a) {
      // OP_RETURN at a real opcode boundary
      lastPos = offset;
      offset += 2;
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

  return lastPos;
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

function encodeStateValue(value: unknown, type: string): string {
  switch (type) {
    case 'int':
    case 'bigint': {
      const n = typeof value === 'bigint' ? value : BigInt(value as number);
      return encodeScriptInt(n);
    }
    case 'bool': {
      return value ? '51' : '00'; // OP_1 (OP_TRUE) or OP_0 (OP_FALSE)
    }
    case 'bytes':
    case 'ByteString': {
      const hex = String(value);
      return encodePushData(hex);
    }
    case 'PubKey': {
      const hex = String(value);
      return encodePushData(hex);
    }
    case 'Ripemd160':
    case 'Addr': {
      const hex = String(value);
      return encodePushData(hex);
    }
    case 'Sha256': {
      const hex = String(value);
      return encodePushData(hex);
    }
    default: {
      // Default: treat as a hex byte string
      const hex = String(value);
      return encodePushData(hex);
    }
  }
}

/**
 * Encode an integer as a Bitcoin Script minimal-encoded number push.
 */
function encodeScriptInt(n: bigint): string {
  if (n === 0n) {
    return '00'; // OP_0
  }

  const negative = n < 0n;
  let absVal = negative ? -n : n;
  const bytes: number[] = [];

  while (absVal > 0n) {
    bytes.push(Number(absVal & 0xffn));
    absVal >>= 8n;
  }

  // If the high bit of the last byte is set, add a sign byte
  if ((bytes[bytes.length - 1]! & 0x80) !== 0) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1]! |= 0x80;
  }

  const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
  return encodePushData(hex);
}

/**
 * Wrap a hex-encoded byte string in a Bitcoin Script push data opcode.
 */
function encodePushData(dataHex: string): string {
  const len = dataHex.length / 2;

  if (len <= 75) {
    return len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xff) {
    return '4c' + len.toString(16).padStart(2, '0') + dataHex;
  } else if (len <= 0xffff) {
    return '4d' + toLittleEndian16(len) + dataHex;
  } else {
    return '4e' + toLittleEndian32(len) + dataHex;
  }
}

function toLittleEndian16(n: number): string {
  return (
    (n & 0xff).toString(16).padStart(2, '0') +
    ((n >> 8) & 0xff).toString(16).padStart(2, '0')
  );
}

function toLittleEndian32(n: number): string {
  return (
    (n & 0xff).toString(16).padStart(2, '0') +
    ((n >> 8) & 0xff).toString(16).padStart(2, '0') +
    ((n >> 16) & 0xff).toString(16).padStart(2, '0') +
    ((n >> 24) & 0xff).toString(16).padStart(2, '0')
  );
}

// ---------------------------------------------------------------------------
// Decoding helpers
// ---------------------------------------------------------------------------

function decodeStateValue(
  hex: string,
  offset: number,
  type: string,
): { value: unknown; bytesRead: number } {
  if (type === 'bool') {
    // Boolean values are encoded as single-byte opcodes:
    // OP_0 (0x00) = false, OP_1/OP_TRUE (0x51) = true
    const opcode = parseInt(hex.slice(offset, offset + 2), 16);
    return { value: opcode !== 0x00, bytesRead: 2 };
  }

  const { data, bytesRead } = decodePushData(hex, offset);

  switch (type) {
    case 'int':
    case 'bigint':
      return { value: decodeScriptInt(data), bytesRead };
    default:
      return { value: data, bytesRead };
  }
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

/**
 * Decode a minimally-encoded Bitcoin Script integer from hex.
 */
function decodeScriptInt(hex: string): bigint {
  if (hex.length === 0 || hex === '00') return 0n;

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

  return negative ? -result : result;
}
