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
import { STATE_FIELD_WIDTHS } from 'runar-ir-schema';

/**
 * Serialize a set of state values into a hex-encoded Bitcoin Script data
 * section (without the OP_RETURN prefix -- that is handled by the caller).
 *
 * Field order is determined by the `index` property of each StateField.
 *
 * Fields with a `fixedArray` annotation are expanded into N element writes
 * in declaration order; callers may supply either a plain array on the
 * grouped name (`values.Board = [...]`) or the underlying scalar fields
 * (`values.Board__0 = ..., values.Board__1 = ..., ...`) — scalars win if
 * both are present, for backward compatibility.
 */
export function serializeState(
  fields: StateField[],
  values: Record<string, unknown>,
): string {
  const sorted = [...fields].sort((a, b) => a.index - b.index);
  let hex = '';

  for (const field of sorted) {
    if (field.fixedArray) {
      const arr = values[field.name];
      const names = field.fixedArray.syntheticNames;
      // Derive the leaf scalar type by peeling off every FixedArray
      // layer from the declared `field.type`. The grouped entry's
      // `elementType` is only the immediate child — for nested arrays
      // it is itself another FixedArray<...>, which `encodeStateValue`
      // does not know how to serialise.
      const leafType = unwrapFixedArrayLeaf(field.type);
      const dims = parseFixedArrayDims(field.type);
      const flatFromArr = Array.isArray(arr) ? flattenNested(arr, dims) : null;
      for (let i = 0; i < names.length; i++) {
        let elem: unknown;
        const synthName = names[i]!;
        if (synthName in values) {
          elem = values[synthName];
        } else if (flatFromArr) {
          elem = flatFromArr[i];
        } else {
          elem = undefined;
        }
        hex += encodeStateValue(elem, leafType, synthName);
      }
    } else {
      const value = values[field.name];
      hex += encodeStateValue(value, field.type, field.name);
    }
  }

  return hex;
}

/**
 * Parse a nested `FixedArray<...>` type string into its outer
 * dimensions: `"FixedArray<FixedArray<bigint, 2>, 3>"` → `[3, 2]`.
 * Non-FixedArray types return `[]`.
 */
function parseFixedArrayDims(type: string): number[] {
  const dims: number[] = [];
  let current = type.trim();
  while (current.startsWith('FixedArray<')) {
    const inner = current.slice('FixedArray<'.length, -1);
    let depth = 0;
    let splitAt = -1;
    for (let i = inner.length - 1; i >= 0; i--) {
      const ch = inner[i]!;
      if (ch === '>') depth++;
      else if (ch === '<') depth--;
      else if (ch === ',' && depth === 0) {
        splitAt = i;
        break;
      }
    }
    if (splitAt < 0) return dims;
    const elemType = inner.slice(0, splitAt).trim();
    const lenStr = inner.slice(splitAt + 1).trim();
    const len = Number.parseInt(lenStr, 10);
    if (!Number.isFinite(len) || len <= 0) return dims;
    dims.push(len);
    current = elemType;
  }
  return dims;
}

/** Return the innermost scalar type of a (possibly nested) FixedArray string. */
function unwrapFixedArrayLeaf(type: string): string {
  let current = type.trim();
  while (current.startsWith('FixedArray<')) {
    const inner = current.slice('FixedArray<'.length, -1);
    let depth = 0;
    let splitAt = -1;
    for (let i = inner.length - 1; i >= 0; i--) {
      const ch = inner[i]!;
      if (ch === '>') depth++;
      else if (ch === '<') depth--;
      else if (ch === ',' && depth === 0) {
        splitAt = i;
        break;
      }
    }
    if (splitAt < 0) return current;
    current = inner.slice(0, splitAt).trim();
  }
  return current;
}

/** Flatten a nested JS array of depth `dims.length` to a flat leaf list. */
function flattenNested(value: unknown, dims: number[]): unknown[] {
  if (dims.length === 0) return [value];
  if (!Array.isArray(value)) {
    const total = dims.reduce((a, b) => a * b, 1);
    return new Array(total).fill(undefined);
  }
  const rest = dims.slice(1);
  const out: unknown[] = [];
  for (const v of value) out.push(...flattenNested(v, rest));
  return out;
}

/** Rebuild a nested JS array of depth `dims.length` from a flat leaf list. */
function regroupNested(flat: unknown[], dims: number[], offset = 0): { value: unknown[]; consumed: number } {
  const [outerLen, ...rest] = dims;
  if (outerLen === undefined) return { value: [], consumed: 0 };
  const value: unknown[] = new Array(outerLen);
  let consumed = 0;
  if (rest.length === 0) {
    for (let i = 0; i < outerLen; i++) value[i] = flat[offset + i];
    consumed = outerLen;
  } else {
    for (let i = 0; i < outerLen; i++) {
      const sub = regroupNested(flat, rest, offset + consumed);
      value[i] = sub.value;
      consumed += sub.consumed;
    }
  }
  return { value, consumed };
}

/**
 * Deserialize state values from a hex-encoded Bitcoin Script data section.
 *
 * The caller must strip the code prefix and OP_RETURN byte before passing
 * the data section.
 *
 * Fields with a `fixedArray` annotation are returned as a plain JS array on
 * the grouped name, not as N individual scalar fields.
 *
 * FAILS CLOSED (C28). The blob is read back out of a locking script that any
 * third party can construct, so it is untrusted input. A state section that
 * does not describe EXACTLY the artifact's `stateFields` is rejected:
 *
 *  - truncation — a field that runs past the end of the blob throws instead of
 *    yielding a short slice (which previously decoded as a plausible-but-wrong
 *    value: a missing `boolean` byte read as `true`, a clipped `bigint` as a
 *    different number, a clipped `PubKey` as a stub key);
 *  - overlong tails — bytes left over after the last declared field throw
 *    instead of being silently dropped.
 *
 * Restoring wrong-but-plausible state from a corrupted continuation is worse
 * than not restoring it at all: the caller then signs a continuation output
 * committing to that state.
 */
export function deserializeState(
  fields: StateField[],
  scriptHex: string,
): Record<string, unknown> {
  if (scriptHex.length % 2 !== 0) {
    throw new Error(
      `deserializeState: state blob is ${scriptHex.length} hex chars — not a whole number of bytes`,
    );
  }

  const sorted = [...fields].sort((a, b) => a.index - b.index);
  const result: Record<string, unknown> = {};
  let offset = 0;

  for (const field of sorted) {
    if (field.fixedArray) {
      const leafType = unwrapFixedArrayLeaf(field.type);
      const dims = parseFixedArrayDims(field.type);
      const total = field.fixedArray.syntheticNames.length;
      const flat: unknown[] = new Array(total);
      for (let i = 0; i < total; i++) {
        const { value, bytesRead } = decodeStateValue(
          scriptHex,
          offset,
          leafType,
          `${field.name}[${i}]`,
        );
        flat[i] = value;
        offset += bytesRead;
      }
      result[field.name] = regroupNested(flat, dims).value;
    } else {
      const { value, bytesRead } = decodeStateValue(scriptHex, offset, field.type, field.name);
      result[field.name] = value;
      offset += bytesRead;
    }
  }

  if (offset !== scriptHex.length) {
    throw new Error(
      `deserializeState: ${(scriptHex.length - offset) / 2} unexpected trailing byte(s) after the ` +
        `last state field (consumed ${offset / 2} of ${scriptHex.length / 2} bytes) — the state ` +
        `section does not match the artifact's stateFields`,
    );
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
function encodeStateValue(value: unknown, type: string, label = '?'): string {
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
      return encodeNum2Bin(n, 8, label);
    }
    case 'bool':
    case 'boolean': {
      // 1 raw byte — matches on-chain serialization (05-stack-lower.ts
      // `case 'boolean': propSizes.push(1)`), decodeStateValue, and the shared
      // STATE_FIELD_WIDTHS table. The canonical Rúnar primitive name is
      // `boolean`; `bool` is accepted as an alias. Without the `boolean` case
      // a real boolean state field fell through to the push-data `default`,
      // silently disagreeing with all three (the descriptor drift #115's
      // review flagged).
      return value ? '01' : '00';
    }
    default: {
      // Fixed-size byte types (PubKey 33, Addr/Ripemd160 20, Sha256 32,
      // Point 64, P256Point 64, P384Point 96): raw hex, no framing needed.
      //
      // Table-driven off the SAME runar-ir-schema table `decodeStateValue`
      // reads, so this writer and that reader cannot drift. It used to be a
      // hand-maintained `case` list, and every type the compiler emitted raw
      // but the list omitted deployed a framed state section the on-chain
      // reader could not parse — the #115 `boolean` drift above, and then
      // P256Point / P384Point, which locked funds on the first spend.
      const rawWidth = STATE_FIELD_WIDTHS[type];
      if (rawWidth?.encoding === 'raw') {
        // Refuse a missing value rather than stringifying it. `String(undefined)`
        // writes the nine characters `undefined` where the artifact declares
        // `rawWidth.size` bytes — not hex, wrong width, and silent. The six peer
        // SDKs refuse this (C-2); TypeScript writing garbage would make the
        // reference implementation the only tier that does.
        //
        // Deliberately NOT applied to the variable-length branch below: an empty
        // ByteString is a legitimate state value that encodes as OP_0, whereas a
        // missing PubKey is not a value at all.
        if (value === undefined || value === null) {
          throw new Error(
            `serializeState: state field "${label}" (${type}) has no value. ` +
              `A raw fixed-width field must carry exactly ${rawWidth.size} bytes; ` +
              `writing a placeholder here would put a state section on chain that ` +
              `the contract's own on-chain reader cannot parse.`,
          );
        }
        return String(value);
      }
      // Variable-length types (bytes, ByteString, etc.): use push-data
      // encoding so the decoder can determine the length.
      const hex = String(value);
      if (hex.length === 0) return '00'; // OP_0
      return encodePushDataState(hex);
    }
  }
}

/**
 * Encode an integer as a fixed-width LE sign-magnitude byte string,
 * matching OP_NUM2BIN behaviour. The sign bit is in the MSB of the last byte.
 *
 * FAILS CLOSED on an out-of-range magnitude. `width` bytes of sign-magnitude
 * hold `8*width - 1` magnitude bits — the top bit of the last byte is the
 * sign. The loop below writes the low `width` bytes and drops everything
 * above, then ORs the sign bit in on top of whatever landed there, so an
 * oversized value used to serialise to a plausible but WRONG word:
 *
 *     2^63      -> 0000000000000080   reads back as 0   (negative zero)
 *     2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
 *     2^64      -> 0000000000000000   reads back as 0
 *
 * The deploy then succeeded and the UTXO was unspendable: the covenant
 * rebuilds the continuation with the compiler's own OP_NUM2BIN 8, which cannot
 * produce those bytes from that number, so hash256(outputs) never matches.
 * Throwing here is the only place a runtime-computed state value can be
 * stopped — `±(2^63 - 1)` remains representable and is unaffected.
 */
function encodeNum2Bin(n: bigint, width: number, label = '?'): string {
  const limit = 1n << BigInt(8 * width - 1);
  if (n >= limit || n <= -limit) {
    throw new Error(
      `serializeState: bigint state field "${label}" = ${n} does not fit the ` +
        `fixed ${width}-byte sign-magnitude state word (magnitude must be ` +
        `< 2^${8 * width - 1}). Serializing it would write a different number ` +
        `into the state section than the contract's on-chain OP_NUM2BIN ` +
        `${width} rebuilds, leaving the output unspendable.`,
    );
  }

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
 * Encode variable-length data as a length-prefixed state-section field.
 *
 * This is the `<len><data>` framing the COMPILER uses on-chain, and it is
 * deliberately NOT the MINIMALDATA push encoding.
 *
 * The state section is raw data living after `OP_RETURN` in the locking
 * script. The interpreter never executes it, so `SCRIPT_VERIFY_MINIMALDATA`
 * — a rule applied to push opcodes as they are executed — does not reach it.
 * What does read it is the compiler's own on-chain state codec:
 * `emitPushDataEncode` in packages/runar-compiler/src/passes/05-stack-lower.ts
 * writes `<len><data>` when rebuilding the continuation, and the on-chain
 * reader parses `<len><data>`. Both sides must agree byte for byte or the
 * `hash256(outputs) == extractOutputHash(preimage)` check fails and the
 * contract is unspendable.
 *
 * #110 briefly applied the MINIMALDATA short-circuit here (1-byte payloads in
 * `{0x01..=0x10, 0x81}` -> `OP_1..OP_16` / `OP_1NEGATE`), changing all seven
 * SDKs and none of the seven compilers. That desynchronised the two sides for
 * exactly those values: a 1-byte `0x05` state field serialised off-chain as
 * `55` while the script rebuilt it as `0105`, so any contract carrying such a
 * value became permanently unspendable — on the WRITE path (continuation hash
 * mismatch) and on the READ path (the on-chain reader takes `0x55` as a
 * length-85 push and dies in OP_SPLIT).
 *
 * MINIMALDATA still applies — and is still enforced — where the interpreter
 * really does execute the push: `encodePushData`/`encodeArg` in contract.ts,
 * which build UNLOCKING scripts. That is the path #110's evidence came from
 * (ByteString call args), and it is unchanged.
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
  label: string,
): { value: unknown; bytesRead: number } {
  // Fixed-width types read exactly `size` raw bytes; widths come from the
  // shared runar-ir-schema table so the codec, the compiler's stateField
  // layout annotations, and verifier tooling can never drift apart.
  const width = STATE_FIELD_WIDTHS[type];
  if (width) {
    const hexWidth = width.size * 2;
    if (offset + hexWidth > hex.length) {
      throw new Error(
        `deserializeState: truncated state — field "${label}" (${type}) needs ${width.size} byte(s) ` +
          `at offset ${offset / 2} but only ${(hex.length - offset) / 2} byte(s) remain`,
      );
    }
    const data = hex.slice(offset, offset + hexWidth);
    switch (width.encoding) {
      case 'bool1':
        // 1 raw byte: 0x00 = false, 0x01 = true
        return { value: data !== '00', bytesRead: hexWidth };
      case 'num2bin-le8':
        // 8 raw bytes LE sign-magnitude (NUM2BIN 8)
        return { value: decodeNum2Bin(data), bytesRead: hexWidth };
      default:
        // Raw fixed-size byte types (PubKey 33, Addr/Ripemd160 20, Sha256 32, Point 64)
        return { value: data, bytesRead: hexWidth };
    }
  }
  // For variable-length / unknown types, fall back to push-data decoding
  const { data, bytesRead } = decodePushData(hex, offset, label);
  return { value: data, bytesRead };
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
 * Decode a state-section field at the given hex offset.
 * Returns the field data (hex) and the total number of hex chars consumed.
 *
 * Exact inverse of `encodePushDataState`, and deliberately as strict as the
 * compiler's on-chain state reader: only `<len><data>` framing is understood.
 * `OP_1..OP_16` (0x51..0x60) and `OP_1NEGATE` (0x4f) are NOT decoded as
 * single-byte values — accepting them here would let the SDK read a state
 * section that the contract's own script cannot parse (the on-chain reader
 * takes 0x55 as a length-85 push), restoring exactly the wrong-but-plausible
 * state C28 exists to prevent. `OP_0` (0x00) falls through to the
 * `opcode <= 75` branch below and correctly decodes as the empty byte array.
 */
function decodePushData(
  hex: string,
  offset: number,
  label: string,
): { data: string; bytesRead: number } {
  /** Assert `chars` hex chars are available from `offset`, else fail closed. */
  const need = (chars: number, what: string): void => {
    if (offset + chars > hex.length) {
      throw new Error(
        `deserializeState: truncated state — field "${label}" ${what} runs past the end of the ` +
          `state section (needs ${chars / 2} byte(s) at offset ${offset / 2}, ` +
          `only ${(hex.length - offset) / 2} remain)`,
      );
    }
  };

  need(2, 'push opcode');
  const opcode = parseInt(hex.slice(offset, offset + 2), 16);
  if (Number.isNaN(opcode)) {
    throw new Error(
      `deserializeState: field "${label}" — non-hex byte at offset ${offset / 2} in the state section`,
    );
  }

  if (opcode <= 75) {
    // Direct push: opcode is the byte length
    const dataLen = opcode * 2;
    need(2 + dataLen, 'push payload');
    return {
      data: hex.slice(offset + 2, offset + 2 + dataLen),
      bytesRead: 2 + dataLen,
    };
  } else if (opcode === 0x4c) {
    // OP_PUSHDATA1
    need(4, 'OP_PUSHDATA1 length prefix');
    const len = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const dataLen = len * 2;
    need(4 + dataLen, 'OP_PUSHDATA1 payload');
    return {
      data: hex.slice(offset + 4, offset + 4 + dataLen),
      bytesRead: 4 + dataLen,
    };
  } else if (opcode === 0x4d) {
    // OP_PUSHDATA2
    need(6, 'OP_PUSHDATA2 length prefix');
    const lo = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const hi = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const len = lo | (hi << 8);
    const dataLen = len * 2;
    need(6 + dataLen, 'OP_PUSHDATA2 payload');
    return {
      data: hex.slice(offset + 6, offset + 6 + dataLen),
      bytesRead: 6 + dataLen,
    };
  } else if (opcode === 0x4e) {
    // OP_PUSHDATA4
    need(10, 'OP_PUSHDATA4 length prefix');
    const b0 = parseInt(hex.slice(offset + 2, offset + 4), 16);
    const b1 = parseInt(hex.slice(offset + 4, offset + 6), 16);
    const b2 = parseInt(hex.slice(offset + 6, offset + 8), 16);
    const b3 = parseInt(hex.slice(offset + 8, offset + 10), 16);
    const len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    const dataLen = len * 2;
    need(10 + dataLen, 'OP_PUSHDATA4 payload');
    return {
      data: hex.slice(offset + 10, offset + 10 + dataLen),
      bytesRead: 10 + dataLen,
    };
  }

  // Not a push opcode at all — `encodePushDataState` can never emit one, so the
  // state section is malformed. Previously this silently consumed one byte and
  // returned an empty value, which desynchronised every subsequent field.
  throw new Error(
    `deserializeState: field "${label}" — byte 0x${opcode.toString(16).padStart(2, '0')} at offset ` +
      `${offset / 2} is not a push opcode; the state section is malformed`,
  );
}

