// ---------------------------------------------------------------------------
// runar-sdk/state.ts — State management for stateful contracts
// ---------------------------------------------------------------------------
//
// Stateful Rúnar contracts embed their state in the locking script as a
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
 * section (without the OP_RETURN prefix — that is handled by the caller).
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

  // The state section begins after OP_RETURN (0x6a). We search for the
  // *last* occurrence of OP_RETURN in the script, since the code section
  // itself could contain 0x6a as part of push data.
  const opReturnByte = '6a';
  const lastOpReturn = scriptHex.lastIndexOf(opReturnByte);
  if (lastOpReturn === -1) {
    return null;
  }

  // State data starts after the OP_RETURN byte
  const stateHex = scriptHex.slice(lastOpReturn + opReturnByte.length);
  return deserializeState(artifact.stateFields, stateHex);
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
      return value ? '0151' : '0100'; // OP_PUSH1 0x51 (OP_TRUE) or 0x00
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
    return '0100'; // OP_PUSH1 0x00
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
  const { data, bytesRead } = decodePushData(hex, offset);

  switch (type) {
    case 'int':
    case 'bigint':
      return { value: decodeScriptInt(data), bytesRead };
    case 'bool':
      return { value: data !== '00' && data !== '', bytesRead };
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

  // Unknown opcode — treat as zero-length
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
