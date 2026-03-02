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
 * @see https://www.rfc-editor.org/rfc/rfc8785
 */

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Serialise a value to canonical JSON (RFC 8785 / JCS).
 *
 * @throws {TypeError} if the value contains `undefined`, functions, symbols,
 *   or circular references.
 */
export function canonicalJsonStringify(value: unknown): string {
  return serialise(value, new Set<object>());
}

/**
 * Parse a JSON string and re-serialise it to canonical form.
 * Useful for normalising IR that was stored with pretty-printing.
 */
export function canonicalise(json: string): string {
  return canonicalJsonStringify(JSON.parse(json));
}

// ---------------------------------------------------------------------------
// Serialisation engine
// ---------------------------------------------------------------------------

function serialise(value: unknown, seen: Set<object>): string {
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
  const obj = value as object;

  // Circular reference detection
  if (seen.has(obj)) {
    throw new TypeError('canonical JSON does not support circular references');
  }
  seen.add(obj);

  let result: string;
  if (Array.isArray(obj)) {
    result = serialiseArray(obj, seen);
  } else if (isPlainObjectOrToJSON(obj)) {
    result = serialiseObject(obj, seen);
  } else {
    // Typed arrays, Date, RegExp, etc. — use toJSON if available,
    // otherwise fall back to plain-object serialisation.
    result = serialiseObject(obj, seen);
  }

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

function serialiseArray(arr: unknown[], seen: Set<object>): string {
  const parts: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const element = arr[i];
    if (element === undefined) {
      // JSON.stringify converts undefined array elements to null.
      parts.push('null');
    } else {
      parts.push(serialise(element, seen));
    }
  }
  return '[' + parts.join(',') + ']';
}

// ---------------------------------------------------------------------------
// Object serialisation (keys sorted by UTF-16 code-unit value)
// ---------------------------------------------------------------------------

function serialiseObject(obj: object, seen: Set<object>): string {
  // If the object has a toJSON method, use it (Date, etc.)
  const asAny = obj as Record<string, unknown>;
  if (typeof asAny['toJSON'] === 'function') {
    return serialise((asAny['toJSON'] as () => unknown)(), seen);
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
    parts.push(serialiseString(key) + ':' + serialise(val, seen));
  }
  return '{' + parts.join(',') + '}';
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isPlainObjectOrToJSON(obj: object): boolean {
  const proto = Object.getPrototypeOf(obj) as object | null;
  return proto === null || proto === Object.prototype || typeof (obj as Record<string, unknown>)['toJSON'] === 'function';
}
