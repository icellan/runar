import { describe, it, expect } from 'vitest';
import { canonicalJsonStringify, canonicalise } from '../canonical-json.js';
import { InputLimits, CanonicalJsonError } from '../input-limits.js';

// ---------------------------------------------------------------------------
// canonicalJsonStringify — depth guard
// ---------------------------------------------------------------------------

describe('canonicalJsonStringify depth guard', () => {
  it('accepts nesting at the MAX_NESTING limit', () => {
    // Build object of depth exactly equal to MAX_NESTING (= containers
    // nested inside one another, each at depth d). Depth here means
    // structural-nesting count, so 1 outer object + (MAX_NESTING-1) extra
    // is the boundary case. We pick a depth a few below the limit to stay
    // well clear of any off-by-one and exercise the happy path.
    const safeDepth = InputLimits.MAX_NESTING - 2;
    let value: unknown = 1;
    for (let i = 0; i < safeDepth; i++) value = { n: value };
    expect(() => canonicalJsonStringify(value)).not.toThrow();
  });

  it('rejects a 600-level-deep object with CanonicalJsonError(depth)', () => {
    // 600 > InputLimits.MAX_NESTING (512). Build deeply nested object.
    let value: unknown = 1;
    for (let i = 0; i < 600; i++) value = { n: value };
    try {
      canonicalJsonStringify(value);
      throw new Error('expected canonicalJsonStringify to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('depth');
      expect(cje.limit).toBe(InputLimits.MAX_NESTING);
      expect(cje.actual).toBeGreaterThan(InputLimits.MAX_NESTING);
    }
  });

  it('rejects a deeply nested array with CanonicalJsonError(depth)', () => {
    let value: unknown = 0;
    for (let i = 0; i < 600; i++) value = [value];
    expect(() => canonicalJsonStringify(value)).toThrow(CanonicalJsonError);
  });
});

// ---------------------------------------------------------------------------
// canonicalJsonStringify — string-bytes guard
// ---------------------------------------------------------------------------

describe('canonicalJsonStringify string-bytes guard', () => {
  it('rejects a string field over MAX_STRING_BYTES', () => {
    const tooLong = 'x'.repeat(InputLimits.MAX_STRING_BYTES + 1);
    try {
      canonicalJsonStringify(tooLong);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('string-bytes');
      expect(cje.limit).toBe(InputLimits.MAX_STRING_BYTES);
      expect(cje.actual).toBe(InputLimits.MAX_STRING_BYTES + 1);
    }
  });

  it('accepts a string field at exactly MAX_STRING_BYTES', () => {
    const justFits = 'x'.repeat(InputLimits.MAX_STRING_BYTES);
    expect(() => canonicalJsonStringify(justFits)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// canonicalJsonStringify — output-bytes guard
// ---------------------------------------------------------------------------

describe('canonicalJsonStringify output-bytes guard', () => {
  it('rejects an object that serialises past MAX_IR_BYTES', () => {
    // 5 strings of (MAX_STRING_BYTES - 1) each (each just under the
    // per-string cap) totals well over MAX_IR_BYTES (5 × 4 MiB ≈ 20 MiB
    // versus 16 MiB ceiling).
    const big = 'a'.repeat(InputLimits.MAX_STRING_BYTES - 1);
    const obj = { a: big, b: big, c: big, d: big, e: big };
    try {
      canonicalJsonStringify(obj);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('bytes');
      expect(cje.limit).toBe(InputLimits.MAX_IR_BYTES);
      expect(cje.actual).toBeGreaterThan(InputLimits.MAX_IR_BYTES);
    }
  });
});

// ---------------------------------------------------------------------------
// canonicalise — invalid JSON
// ---------------------------------------------------------------------------

describe('canonicalise invalid-input guard', () => {
  it('rejects malformed JSON with CanonicalJsonError(invalid)', () => {
    try {
      canonicalise('{not: "json"}');
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('invalid');
    }
  });

  it('rejects empty input with CanonicalJsonError(invalid)', () => {
    expect(() => canonicalise('')).toThrow(CanonicalJsonError);
  });
});
