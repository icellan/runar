/**
 * State-tail byte layout — the single source of truth for WHERE each
 * serialized state field lives in a stateful contract's locking script.
 *
 * Mirrors the SDK's `serializeState` wire format exactly:
 *
 *   <code part> OP_RETURN <field0> <field1> ... <fieldN>
 *
 *   - bigint / int : 8 raw bytes, little-endian sign-magnitude (OP_NUM2BIN 8)
 *   - bool         : 1 raw byte (0x00 / 0x01)
 *   - PubKey       : 33 raw bytes          - Addr / Ripemd160 : 20 raw bytes
 *   - Sha256       : 32 raw bytes          - Point            : 64 raw bytes
 *   - P256Point    : 64 raw bytes          - P384Point        : 96 raw bytes
 *   - anything else: push-data framed (variable length)
 *
 * The curve-point types are raw and fixed-width because `runar-lang`'s
 * `P256Point` / `P384Point` cast constructors hard-assert 64 / 96 bytes, and
 * all seven COMPILERS emit them as fixed raw slices in the state tail. An SDK
 * that push-data frames them instead deploys a state section one (64 -> 0x40)
 * or two (96 -> OP_PUSHDATA1) bytes longer than the script's own reader
 * expects, and the first spend fails with the funds locked.
 *
 * Fields are concatenated in `StateField.index` order. FixedArray fields
 * serialize as their flattened leaves back-to-back.
 *
 * Lives in runar-ir-schema so the compiler (which annotates `stateFields`
 * in the artifact), the SDK's state codec, and any verifier tooling share
 * ONE width table instead of re-deriving it.
 */

import type { StateField } from './artifact.js';

export type StateFieldEncoding = NonNullable<StateField['encoding']>;

/**
 * Fixed serialized widths (bytes) for scalar state-field types.
 * Types absent from this table serialize as push-data framed variable-length
 * values ('pushdata').
 */
export const STATE_FIELD_WIDTHS: Readonly<
  Record<string, { readonly size: number; readonly encoding: StateFieldEncoding }>
> = {
  int: { size: 8, encoding: 'num2bin-le8' },
  bigint: { size: 8, encoding: 'num2bin-le8' },
  bool: { size: 1, encoding: 'bool1' },
  boolean: { size: 1, encoding: 'bool1' },
  PubKey: { size: 33, encoding: 'raw' },
  Addr: { size: 20, encoding: 'raw' },
  Ripemd160: { size: 20, encoding: 'raw' },
  Sha256: { size: 32, encoding: 'raw' },
  Point: { size: 64, encoding: 'raw' },
  P256Point: { size: 64, encoding: 'raw' },
  P384Point: { size: 96, encoding: 'raw' },
};

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

/**
 * Annotate state fields with their byte layout (`encoding`, `byteOffset`,
 * `byteLength`, `tailOffset`). Returns NEW field objects (inputs are not
 * mutated), sorted by `index` — the serialization order.
 *
 * `byteOffset` counts from the byte AFTER the OP_RETURN separator and is
 * present only while every preceding field is fixed-length. `tailOffset` is
 * a NEGATIVE offset from the END of the locking script and is present only
 * when the field itself and every following field is fixed-length.
 */
export function annotateStateFieldLayout(fields: StateField[]): StateField[] {
  const sorted = [...fields].sort((a, b) => a.index - b.index);

  const out: StateField[] = sorted.map(field => {
    const annotated: StateField = { ...field };
    if (field.fixedArray) {
      // Flattened leaves serialize back-to-back; fixed only if the leaf is.
      const leaf = STATE_FIELD_WIDTHS[unwrapFixedArrayLeaf(field.type)];
      const count = field.fixedArray.syntheticNames.length;
      if (leaf) {
        annotated.encoding = leaf.encoding;
        annotated.byteLength = leaf.size * count;
      } else {
        annotated.encoding = 'pushdata';
      }
      return annotated;
    }
    const fixed = STATE_FIELD_WIDTHS[field.type];
    if (fixed) {
      annotated.encoding = fixed.encoding;
      annotated.byteLength = fixed.size;
    } else {
      annotated.encoding = 'pushdata';
    }
    return annotated;
  });

  // Forward pass: byteOffset while all preceding fields are fixed-length.
  let offset = 0;
  let frontFixed = true;
  for (const f of out) {
    if (frontFixed) f.byteOffset = offset;
    if (f.byteLength === undefined) {
      frontFixed = false;
    } else {
      offset += f.byteLength;
    }
  }

  // Backward pass: tailOffset while the field and all following are fixed.
  let fromEnd = 0;
  for (let i = out.length - 1; i >= 0; i--) {
    const f = out[i]!;
    if (f.byteLength === undefined) break;
    fromEnd += f.byteLength;
    f.tailOffset = -fromEnd;
  }

  return out;
}

/**
 * Total serialized state length in bytes (after the OP_RETURN byte), or
 * undefined when any field is variable-length.
 */
export function totalStateByteLength(fields: StateField[]): number | undefined {
  let total = 0;
  for (const f of annotateStateFieldLayout(fields)) {
    if (f.byteLength === undefined) return undefined;
    total += f.byteLength;
  }
  return total;
}
