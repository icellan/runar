import { describe, it, expect } from 'vitest';
import { canonicalJsonStringify, canonicalise } from '../canonical-json.js';

// ---------------------------------------------------------------------------
// Sorted key ordering
// ---------------------------------------------------------------------------

describe('sorted key ordering', () => {
  it('sorts object keys alphabetically', () => {
    const result = canonicalJsonStringify({ z: 1, a: 2, m: 3 });
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it('sorts nested object keys', () => {
    const result = canonicalJsonStringify({ b: { y: 1, x: 2 }, a: 3 });
    expect(result).toBe('{"a":3,"b":{"x":2,"y":1}}');
  });

  it('sorts keys by UTF-16 code-unit value (uppercase before lowercase)', () => {
    // In UTF-16, uppercase letters (A=0x41) come before lowercase (a=0x61)
    const result = canonicalJsonStringify({ a: 1, A: 2 });
    expect(result).toBe('{"A":2,"a":1}');
  });

  it('sorts keys with numbers correctly', () => {
    const result = canonicalJsonStringify({ '2': 'b', '10': 'c', '1': 'a' });
    expect(result).toBe('{"1":"a","10":"c","2":"b"}');
  });

  it('handles empty objects', () => {
    expect(canonicalJsonStringify({})).toBe('{}');
  });

  it('handles deeply nested sorting', () => {
    const input = { c: { f: { i: 1, h: 2 }, e: 3 }, a: 4 };
    const result = canonicalJsonStringify(input);
    expect(result).toBe('{"a":4,"c":{"e":3,"f":{"h":2,"i":1}}}');
  });
});

// ---------------------------------------------------------------------------
// No whitespace
// ---------------------------------------------------------------------------

describe('no whitespace', () => {
  it('produces no spaces or newlines in objects', () => {
    const result = canonicalJsonStringify({ a: 1, b: 2 });
    expect(result).not.toMatch(/\s/);
  });

  it('produces no spaces or newlines in arrays', () => {
    const result = canonicalJsonStringify([1, 2, 3]);
    expect(result).not.toMatch(/\s/);
    expect(result).toBe('[1,2,3]');
  });

  it('produces no whitespace in nested structures', () => {
    const result = canonicalJsonStringify({ a: [1, { b: 2 }] });
    expect(result).not.toMatch(/[\n\r\t]/);
    // The only spaces should be inside strings, not structural whitespace
    expect(result).toBe('{"a":[1,{"b":2}]}');
  });
});

// ---------------------------------------------------------------------------
// Bigint serialization
// ---------------------------------------------------------------------------

describe('bigint serialization', () => {
  it('serialises bigint as bare integer', () => {
    expect(canonicalJsonStringify(42n)).toBe('42');
  });

  it('serialises zero bigint', () => {
    expect(canonicalJsonStringify(0n)).toBe('0');
  });

  it('serialises negative bigint', () => {
    expect(canonicalJsonStringify(-100n)).toBe('-100');
  });

  it('serialises very large bigint', () => {
    const big = 2n ** 256n;
    expect(canonicalJsonStringify(big)).toBe(big.toString());
  });

  it('serialises bigint inside objects', () => {
    expect(canonicalJsonStringify({ value: 99n })).toBe('{"value":99}');
  });

  it('serialises bigint inside arrays', () => {
    expect(canonicalJsonStringify([1n, 2n, 3n])).toBe('[1,2,3]');
  });
});

// ---------------------------------------------------------------------------
// Circular reference detection
// ---------------------------------------------------------------------------

describe('circular reference detection', () => {
  it('throws on directly circular object', () => {
    const obj: Record<string, unknown> = {};
    obj['self'] = obj;
    expect(() => canonicalJsonStringify(obj)).toThrow('circular');
  });

  it('throws on indirectly circular objects', () => {
    const a: Record<string, unknown> = {};
    const b: Record<string, unknown> = { ref: a };
    a['ref'] = b;
    expect(() => canonicalJsonStringify(a)).toThrow('circular');
  });

  it('throws on circular arrays', () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr);
    expect(() => canonicalJsonStringify(arr)).toThrow('circular');
  });

  it('does not false-positive on objects appearing at different paths', () => {
    // Same object referenced twice but not circularly
    const shared = { x: 1 };
    const obj = { a: shared, b: shared };
    // This should NOT throw
    expect(() => canonicalJsonStringify(obj)).not.toThrow();
    expect(canonicalJsonStringify(obj)).toBe('{"a":{"x":1},"b":{"x":1}}');
  });
});

// ---------------------------------------------------------------------------
// Negative zero handling
// ---------------------------------------------------------------------------

describe('-0 handling', () => {
  it('serialises -0 as "0"', () => {
    expect(canonicalJsonStringify(-0)).toBe('0');
  });

  it('serialises -0 inside an array as 0', () => {
    expect(canonicalJsonStringify([-0])).toBe('[0]');
  });

  it('serialises -0 inside an object as 0', () => {
    expect(canonicalJsonStringify({ n: -0 })).toBe('{"n":0}');
  });
});

// ---------------------------------------------------------------------------
// NaN and Infinity rejection
// ---------------------------------------------------------------------------

describe('NaN / Infinity rejection', () => {
  it('rejects NaN', () => {
    expect(() => canonicalJsonStringify(NaN)).toThrow();
  });

  it('rejects Infinity', () => {
    expect(() => canonicalJsonStringify(Infinity)).toThrow();
  });

  it('rejects -Infinity', () => {
    expect(() => canonicalJsonStringify(-Infinity)).toThrow();
  });

  it('rejects NaN inside objects', () => {
    expect(() => canonicalJsonStringify({ x: NaN })).toThrow();
  });

  it('rejects Infinity inside arrays', () => {
    expect(() => canonicalJsonStringify([Infinity])).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Undefined handling
// ---------------------------------------------------------------------------

describe('undefined handling', () => {
  it('throws for top-level undefined', () => {
    expect(() => canonicalJsonStringify(undefined)).toThrow();
  });

  it('skips undefined values in objects', () => {
    const result = canonicalJsonStringify({ a: 1, b: undefined, c: 3 });
    expect(result).toBe('{"a":1,"c":3}');
  });

  it('converts undefined in arrays to null', () => {
    const arr = [1, undefined, 3];
    const result = canonicalJsonStringify(arr);
    expect(result).toBe('[1,null,3]');
  });
});

// ---------------------------------------------------------------------------
// Null handling
// ---------------------------------------------------------------------------

describe('null handling', () => {
  it('serialises null', () => {
    expect(canonicalJsonStringify(null)).toBe('null');
  });

  it('serialises null in arrays', () => {
    expect(canonicalJsonStringify([null, null])).toBe('[null,null]');
  });

  it('serialises null in objects', () => {
    expect(canonicalJsonStringify({ a: null })).toBe('{"a":null}');
  });
});

// ---------------------------------------------------------------------------
// Other primitive values
// ---------------------------------------------------------------------------

describe('primitive values', () => {
  it('serialises booleans', () => {
    expect(canonicalJsonStringify(true)).toBe('true');
    expect(canonicalJsonStringify(false)).toBe('false');
  });

  it('serialises numbers', () => {
    expect(canonicalJsonStringify(42)).toBe('42');
    expect(canonicalJsonStringify(3.14)).toBe('3.14');
    expect(canonicalJsonStringify(0)).toBe('0');
  });

  it('serialises strings', () => {
    expect(canonicalJsonStringify('hello')).toBe('"hello"');
  });

  it('escapes special characters in strings', () => {
    expect(canonicalJsonStringify('line\nbreak')).toBe('"line\\nbreak"');
  });

  it('rejects symbols', () => {
    expect(() => canonicalJsonStringify(Symbol('test'))).toThrow();
  });

  it('rejects functions', () => {
    expect(() => canonicalJsonStringify(() => {})).toThrow();
  });
});

// ---------------------------------------------------------------------------
// canonicalise (parse + re-serialize)
// ---------------------------------------------------------------------------

describe('canonicalise', () => {
  it('normalises pretty-printed JSON', () => {
    const pretty = JSON.stringify({ z: 1, a: 2 }, null, 2);
    expect(canonicalise(pretty)).toBe('{"a":2,"z":1}');
  });

  it('is idempotent on already-canonical JSON', () => {
    const canonical = '{"a":1,"b":2}';
    expect(canonicalise(canonical)).toBe(canonical);
  });
});

// ---------------------------------------------------------------------------
// Objects with toJSON
// ---------------------------------------------------------------------------

describe('objects with toJSON', () => {
  it('uses toJSON() if present', () => {
    const obj = {
      toJSON() {
        return { x: 1 };
      },
    };
    expect(canonicalJsonStringify(obj)).toBe('{"x":1}');
  });
});

// ---------------------------------------------------------------------------
// Empty structures
// ---------------------------------------------------------------------------

describe('empty structures', () => {
  it('handles empty array', () => {
    expect(canonicalJsonStringify([])).toBe('[]');
  });

  it('handles empty object', () => {
    expect(canonicalJsonStringify({})).toBe('{}');
  });

  it('handles nested empty structures', () => {
    expect(canonicalJsonStringify({ a: [], b: {} })).toBe('{"a":[],"b":{}}');
  });
});
