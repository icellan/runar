/**
 * Shared Bitcoin Script push-data encoding helpers.
 *
 * Extracted from `06-emit.ts` so that other passes (notably the
 * array-form `asm({ body: [OP_DUP, push(...), ...] })` parser in
 * `01-parse.ts`) can compute the exact byte encoding a literal would
 * receive at emit time, without duplicating the script-number / push-
 * data encoding rules.
 *
 * The encoder is deliberately the SAME function used by the emit
 * pass — any future change to push-data encoding must therefore land
 * here (a single source of truth) so the array-form body and the
 * eventual emitted bytes stay byte-identical.
 */

// ---------------------------------------------------------------------------
// Hex utilities
// ---------------------------------------------------------------------------

export function byteToHex(b: number): string {
  return b.toString(16).padStart(2, '0');
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const b of bytes) {
    hex += byteToHex(b);
  }
  return hex;
}

// ---------------------------------------------------------------------------
// Script number encoding
// ---------------------------------------------------------------------------

/**
 * Encode a bigint as a Bitcoin Script number (little-endian, sign bit in MSB).
 *
 * - 0 is the empty byte array
 * - positive: little-endian bytes, MSB's high bit clear
 * - negative: little-endian bytes, MSB's high bit set
 * - if the high bit of the most significant byte is already set, append
 *   an extra 0x00 (positive) or 0x80 (negative) byte for the sign bit
 */
export function encodeScriptNumber(n: bigint): Uint8Array {
  if (n === 0n) {
    return new Uint8Array(0);
  }

  const negative = n < 0n;
  let abs = negative ? -n : n;

  const bytes: number[] = [];
  while (abs > 0n) {
    bytes.push(Number(abs & 0xffn));
    abs >>= 8n;
  }

  const lastByte = bytes[bytes.length - 1]!;
  if (lastByte & 0x80) {
    bytes.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    bytes[bytes.length - 1] = lastByte | 0x80;
  }

  return new Uint8Array(bytes);
}

// ---------------------------------------------------------------------------
// Push data encoding
// ---------------------------------------------------------------------------

/**
 * Encode a push-data operation as Bitcoin Script bytes.
 *
 * - len 1..75   : single-byte length prefix + data
 * - len 76..255 : OP_PUSHDATA1 (0x4c) + 1-byte length + data
 * - len 256..65535: OP_PUSHDATA2 (0x4d) + 2-byte LE length + data
 * - len > 65535 : OP_PUSHDATA4 (0x4e) + 4-byte LE length + data
 * - len 0       : OP_0 (single 0x00 byte)
 */
export function encodePushData(data: Uint8Array): Uint8Array {
  const len = data.length;

  if (len === 0) {
    return new Uint8Array([0x00]);
  }

  if (len >= 1 && len <= 75) {
    const result = new Uint8Array(1 + len);
    result[0] = len;
    result.set(data, 1);
    return result;
  }

  if (len >= 76 && len <= 255) {
    const result = new Uint8Array(2 + len);
    result[0] = 0x4c; // OP_PUSHDATA1
    result[1] = len;
    result.set(data, 2);
    return result;
  }

  if (len >= 256 && len <= 65535) {
    const result = new Uint8Array(3 + len);
    result[0] = 0x4d; // OP_PUSHDATA2
    result[1] = len & 0xff;
    result[2] = (len >> 8) & 0xff;
    result.set(data, 3);
    return result;
  }

  // OP_PUSHDATA4
  const result = new Uint8Array(5 + len);
  result[0] = 0x4e;
  result[1] = len & 0xff;
  result[2] = (len >> 8) & 0xff;
  result[3] = (len >> 16) & 0xff;
  result[4] = (len >> 24) & 0xff;
  result.set(data, 5);
  return result;
}

/**
 * Encode a bigint push as a Bitcoin Script byte sequence (hex string).
 *
 * Uses small-integer opcodes where possible (OP_0, OP_1NEGATE, OP_1..OP_16);
 * falls back to a length-prefixed push of the script-number encoding.
 */
export function encodePushBigIntHex(n: bigint): string {
  if (n === 0n) {
    return '00'; // OP_0
  }
  if (n === -1n) {
    return '4f'; // OP_1NEGATE
  }
  if (n >= 1n && n <= 16n) {
    return byteToHex(0x50 + Number(n)); // OP_1..OP_16
  }
  const numBytes = encodeScriptNumber(n);
  return bytesToHex(encodePushData(numBytes));
}

/**
 * Encode a raw byte-array push (MINIMALDATA aware) as a hex string.
 *
 * Mirrors `encodePushValue(Uint8Array)` in `06-emit.ts`:
 * - empty -> OP_0 ('00')
 * - single byte 1..16 -> OP_1..OP_16
 * - single byte 0x81 -> OP_1NEGATE
 * - else length-prefixed push (with OP_PUSHDATA{1,2,4} as needed)
 *
 * Note: 0x00 is NOT converted to OP_0 because OP_0 pushes [] not [0x00].
 */
export function encodePushBytesHex(value: Uint8Array): string {
  if (value.length === 0) {
    return '00'; // OP_0
  }
  if (value.length === 1) {
    const b = value[0]!;
    if (b >= 1 && b <= 16) return byteToHex(0x50 + b);
    if (b === 0x81) return '4f'; // OP_1NEGATE
  }
  return bytesToHex(encodePushData(value));
}
