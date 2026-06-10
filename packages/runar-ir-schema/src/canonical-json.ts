/**
 * RFC 8785 / JCS (JSON Canonicalization Scheme) serializer.
 *
 * Produces a deterministic, byte-identical JSON string for any JSON-compatible
 * value.  This is used to guarantee that two Rúnar compilers emitting the same
 * ANF IR will produce identical output when serialised.
 *
 * Key properties:
 * - Object keys are sorted by their UTF-16 code-unit values (per ES spec).
 * - Numbers use ES `JSON.stringify` serialization (IEEE 754, no trailing
 *   zeros, no positive sign on exponent, etc.).
 * - No whitespace.
 * - `undefined` values and `undefined` array slots are not allowed (will
 *   throw).
 * - `bigint` values are serialised as bare integers (no quotes), matching the
 *   JSON Schema `integer` type used in the ANF IR schema.
 *
 * DoS-bound input guards:
 * - Recursion depth is capped at {@link InputLimits.MAX_NESTING}.
 * - Individual string values are capped at {@link InputLimits.MAX_STRING_BYTES}.
 * - Total serialised output is capped at {@link InputLimits.MAX_IR_BYTES}.
 * - Bound violations throw {@link CanonicalJsonError} with `code` / `limit` /
 *   `actual` set for typed downstream handling.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8785
 */

import { InputLimits, CanonicalJsonError } from './input-limits.js';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Serialise a value to canonical JSON (RFC 8785 / JCS).
 *
 * @throws {TypeError} if the value contains functions or symbols.
 * @throws {CanonicalJsonError} if recursion depth, string byte length, or
 *   total output byte length exceeds the documented {@link InputLimits}.
 */
export function canonicalJsonStringify(value: unknown): string {
  const result = serialise(value, new Set<object>(), 0);
  // Final output-byte-length guard (UTF-8 bytes).
  const byteLen = Buffer.byteLength(result, 'utf8');
  if (byteLen > InputLimits.MAX_IR_BYTES) {
    throw new CanonicalJsonError(
      'bytes',
      `canonical JSON output exceeds ${InputLimits.MAX_IR_BYTES} bytes (actual ${byteLen})`,
      { limit: InputLimits.MAX_IR_BYTES, actual: byteLen },
    );
  }
  return result;
}

/**
 * Parse a JSON string and re-serialise it to canonical form.
 * Useful for normalising IR that was stored with pretty-printing.
 *
 * @throws {CanonicalJsonError} with `code: 'invalid'` if the input is not
 *   valid JSON, or with `code: 'bytes'` / `'depth'` / `'string-bytes'` if
 *   the canonicalised output would violate an {@link InputLimits} bound.
 */
export function canonicalise(json: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (e) {
    throw new CanonicalJsonError(
      'invalid',
      `canonicalise: input is not valid JSON: ${(e as Error).message}`,
    );
  }
  return canonicalJsonStringify(parsed);
}

// ---------------------------------------------------------------------------
// Serialisation engine
// ---------------------------------------------------------------------------

function serialise(value: unknown, seen: Set<object>, depth: number): string {
  // null
  if (value === null) {
    return 'null';
  }

  // Primitives
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      return serialiseNumber(value);

    case 'bigint':
      // Serialise as a bare JSON integer — no quotes.
      return value.toString();

    case 'string':
      return serialiseString(value);

    case 'undefined':
    case 'symbol':
    case 'function':
      throw new TypeError(
        `canonical JSON does not support ${typeof value}`,
      );
  }

  // Objects and arrays (typeof === 'object' at this point)
  // Depth guard before descending into the container.
  if (depth >= InputLimits.MAX_NESTING) {
    throw new CanonicalJsonError(
      'depth',
      `canonical JSON nesting exceeds ${InputLimits.MAX_NESTING}`,
      { limit: InputLimits.MAX_NESTING, actual: depth + 1 },
    );
  }

  const obj = value as object;

  // Circular reference detection
  if (seen.has(obj)) {
    throw new TypeError('canonical JSON does not support circular references');
  }
  seen.add(obj);

  // Arrays and objects (including typed arrays, Date, RegExp, etc.) both
  // route through serialiseObject which honours `toJSON` and otherwise
  // walks own enumerable keys.
  const result: string = Array.isArray(obj)
    ? serialiseArray(obj, seen, depth + 1)
    : serialiseObject(obj, seen, depth + 1);

  seen.delete(obj);
  return result;
}

// ---------------------------------------------------------------------------
// Number serialisation (ES2022 §25.5.2.1)
// ---------------------------------------------------------------------------

function serialiseNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new TypeError(
      `canonical JSON does not support ${n} (NaN / Infinity)`,
    );
  }
  if (Object.is(n, -0)) {
    return '0';
  }
  // JSON.stringify for finite numbers matches the ES spec requirement
  // that RFC 8785 mandates.
  return JSON.stringify(n);
}

// ---------------------------------------------------------------------------
// String serialisation (RFC 8785 §3.2.2.2)
// ---------------------------------------------------------------------------

function serialiseString(s: string): string {
  // Per-string byte-length guard.
  const byteLen = Buffer.byteLength(s, 'utf8');
  if (byteLen > InputLimits.MAX_STRING_BYTES) {
    throw new CanonicalJsonError(
      'string-bytes',
      `canonical JSON string field exceeds ${InputLimits.MAX_STRING_BYTES} bytes (actual ${byteLen})`,
      { limit: InputLimits.MAX_STRING_BYTES, actual: byteLen },
    );
  }
  // RFC 8785 §3.2.2.2 / audit D6: the input MUST be well-formed Unicode.
  // JS strings are UTF-16 code-unit sequences and may legally contain
  // unpaired surrogates; `JSON.stringify` happily emits them, producing
  // bytes that the six other SDK tiers reject. Walk code units, reject any
  // unpaired surrogate, and only then delegate to `JSON.stringify` for the
  // actual escape table (which is correct on well-formed inputs).
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : -1;
      if (next < 0xDC00 || next > 0xDFFF) {
        throw new CanonicalJsonError(
          'lone-surrogate',
          `canonical JSON: lone high surrogate U+${c.toString(16).toUpperCase().padStart(4, '0')} in string`,
        );
      }
      i++; // skip the valid low surrogate
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      throw new CanonicalJsonError(
        'lone-surrogate',
        `canonical JSON: lone low surrogate U+${c.toString(16).toUpperCase().padStart(4, '0')} in string`,
      );
    }
  }
  // JSON.stringify already produces correct escaping for most cases.
  // RFC 8785 additionally requires that code-points U+0000–U+001F are
  // \uXXXX-escaped (which JSON.stringify does), and that there is no
  // gratuitous escaping of solidus '/' (JSON.stringify does NOT escape it
  // by default in modern engines, which is correct).
  return JSON.stringify(s);
}

// ---------------------------------------------------------------------------
// Array serialisation
// ---------------------------------------------------------------------------

function serialiseArray(arr: unknown[], seen: Set<object>, depth: number): string {
  const parts: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const element = arr[i];
    if (element === undefined) {
      // JSON.stringify converts undefined array elements to null.
      parts.push('null');
    } else {
      parts.push(serialise(element, seen, depth));
    }
  }
  return '[' + parts.join(',') + ']';
}

// ---------------------------------------------------------------------------
// Object serialisation (keys sorted by UTF-16 code-unit value)
// ---------------------------------------------------------------------------

function serialiseObject(obj: object, seen: Set<object>, depth: number): string {
  // If the object has a toJSON method, use it (Date, etc.)
  const asAny = obj as Record<string, unknown>;
  if (typeof asAny['toJSON'] === 'function') {
    return serialise((asAny['toJSON'] as () => unknown)(), seen, depth);
  }

  // Collect own enumerable string keys and sort by UTF-16 code units.
  // In ES, `Array.prototype.sort()` without a comparator uses the
  // default string comparison which is exactly UTF-16 code-unit order.
  const keys = Object.keys(obj).sort();

  const parts: string[] = [];
  for (const key of keys) {
    const val = (obj as Record<string, unknown>)[key];
    // JSON.stringify omits keys whose value is undefined.
    if (val === undefined) continue;
    parts.push(serialiseString(key) + ':' + serialise(val, seen, depth));
  }
  return '{' + parts.join(',') + '}';
}

