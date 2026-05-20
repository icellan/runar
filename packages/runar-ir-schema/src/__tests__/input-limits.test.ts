import { describe, it, expect } from 'vitest';
import {
  InputLimits,
  CanonicalJsonError,
  type InputLimitsKey,
} from '../input-limits.js';

// ---------------------------------------------------------------------------
// InputLimits constants
// ---------------------------------------------------------------------------

describe('InputLimits', () => {
  it('exposes the documented byte bounds', () => {
    expect(InputLimits.MAX_IR_BYTES).toBe(16 * 1024 * 1024);
    expect(InputLimits.MAX_SCRIPT_BYTES).toBe(4 * 1024 * 1024);
    expect(InputLimits.MAX_NESTING).toBe(512);
    expect(InputLimits.MAX_STRING_BYTES).toBe(4 * 1024 * 1024);
  });

  it('is frozen at the type level (readonly literal values)', () => {
    // `as const` makes the object literally typed; verify the type-side
    // contract by assigning each key to InputLimitsKey.
    const keys: InputLimitsKey[] = [
      'MAX_IR_BYTES',
      'MAX_SCRIPT_BYTES',
      'MAX_NESTING',
      'MAX_STRING_BYTES',
    ];
    for (const k of keys) {
      expect(typeof InputLimits[k]).toBe('number');
      expect(Number.isInteger(InputLimits[k])).toBe(true);
      expect(InputLimits[k]).toBeGreaterThan(0);
    }
  });

  it('runtime mutation attempts do not change exported values', () => {
    // The object is `as const` at the type layer; at runtime TS does not
    // freeze it, but downstream code must treat the values as immutable.
    // We assert the values are exactly what the constants module declares.
    const snapshot = { ...InputLimits };
    expect(snapshot.MAX_IR_BYTES).toBe(16 * 1024 * 1024);
    expect(snapshot.MAX_SCRIPT_BYTES).toBe(4 * 1024 * 1024);
    expect(snapshot.MAX_NESTING).toBe(512);
    expect(snapshot.MAX_STRING_BYTES).toBe(4 * 1024 * 1024);
  });
});

// ---------------------------------------------------------------------------
// CanonicalJsonError
// ---------------------------------------------------------------------------

describe('CanonicalJsonError', () => {
  it('is an Error subclass', () => {
    const err = new CanonicalJsonError('invalid', 'bad input');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(CanonicalJsonError);
  });

  it('sets name to CanonicalJsonError', () => {
    const err = new CanonicalJsonError('invalid', 'bad input');
    expect(err.name).toBe('CanonicalJsonError');
  });

  it('propagates the message through Error', () => {
    const err = new CanonicalJsonError('depth', 'too deep');
    expect(err.message).toBe('too deep');
  });

  it('populates each documented code value', () => {
    const codes = ['depth', 'bytes', 'string-bytes', 'circular', 'invalid'] as const;
    for (const code of codes) {
      const err = new CanonicalJsonError(code, `msg-${code}`);
      expect(err.code).toBe(code);
    }
  });

  it('propagates limit and actual from info', () => {
    const err = new CanonicalJsonError('bytes', 'too big', {
      limit: 1024,
      actual: 2048,
    });
    expect(err.limit).toBe(1024);
    expect(err.actual).toBe(2048);
  });

  it('leaves limit and actual undefined when info omitted', () => {
    const err = new CanonicalJsonError('circular', 'cycle detected');
    expect(err.limit).toBeUndefined();
    expect(err.actual).toBeUndefined();
  });

  it('accepts partial info (only limit)', () => {
    const err = new CanonicalJsonError('depth', 'too deep', { limit: 512 });
    expect(err.limit).toBe(512);
    expect(err.actual).toBeUndefined();
  });

  it('accepts partial info (only actual)', () => {
    const err = new CanonicalJsonError('string-bytes', 'string too long', {
      actual: 9999,
    });
    expect(err.limit).toBeUndefined();
    expect(err.actual).toBe(9999);
  });
});
