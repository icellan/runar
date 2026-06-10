import { describe, it, expect } from 'vitest';
import { loadANFFromJSON } from '../index.js';
import { parse } from '../passes/01-parse.js';
import { InputLimits, CanonicalJsonError } from 'runar-ir-schema';

describe('loadANFFromJSON size guards', () => {
  it('rejects IR JSON over MAX_IR_BYTES with CanonicalJsonError(bytes)', () => {
    // Build a string just over the cap. Content does not need to be
    // valid JSON — the size guard runs before JSON.parse.
    const oversized = 'x'.repeat(InputLimits.MAX_IR_BYTES + 1);
    try {
      loadANFFromJSON(oversized);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('bytes');
      expect(cje.limit).toBe(InputLimits.MAX_IR_BYTES);
      expect(cje.actual).toBe(InputLimits.MAX_IR_BYTES + 1);
    }
  });

  it('wraps malformed JSON in CanonicalJsonError(invalid)', () => {
    try {
      loadANFFromJSON('{not: "valid"}');
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('invalid');
    }
  });

  it('rejects deeply nested IR with CanonicalJsonError(depth)', () => {
    // Build a JSON string nested 600 levels deep ({"n":{"n":{...}}}}).
    // 600 > InputLimits.MAX_NESTING (512).
    let body = '1';
    for (let i = 0; i < 600; i++) body = '{"n":' + body + '}';
    // Wrap in valid top-level program-shape so other checks don't fire
    // first; nesting is the field-value of "methods" itself isn't a list
    // so we put nesting under "contractName" indirectly via a fake top:
    // simpler: build a top-level array of one super-deep object.
    const json = body;
    try {
      loadANFFromJSON(json);
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('depth');
      expect(cje.limit).toBe(InputLimits.MAX_NESTING);
    }
  });

  it('accepts a legitimate minimal IR program (well under all caps)', () => {
    const minimal = JSON.stringify({
      contractName: 'X',
      properties: [],
      methods: [],
    });
    expect(() => loadANFFromJSON(minimal)).not.toThrow();
  });
});

describe('parse() source size guard', () => {
  it('rejects source over MAX_SOURCE_BYTES with CanonicalJsonError(bytes)', () => {
    // Build a string just over the cap. Content does not need to be
    // valid TS source — the size guard runs before the tokenizer.
    const oversized = 'x'.repeat(InputLimits.MAX_SOURCE_BYTES + 1);
    try {
      parse(oversized, 'contract.runar.ts');
      throw new Error('expected throw');
    } catch (err) {
      expect(err).toBeInstanceOf(CanonicalJsonError);
      const cje = err as CanonicalJsonError;
      expect(cje.code).toBe('bytes');
      expect(cje.limit).toBe(InputLimits.MAX_SOURCE_BYTES);
      expect(cje.actual).toBe(InputLimits.MAX_SOURCE_BYTES + 1);
    }
  });

  it('rejects oversized source independent of extension dispatch', () => {
    // The byte cap fires before extension dispatch, so an obviously-
    // wrong extension still gets caught.
    const oversized = 'x'.repeat(InputLimits.MAX_SOURCE_BYTES + 1);
    expect(() => parse(oversized, 'contract.runar.py')).toThrow(CanonicalJsonError);
  });

  it('accepts a minimal well-formed source under the cap', () => {
    const minimal =
      'class Counter extends SmartContract {\n' +
      '  public readonly x: bigint;\n' +
      '  constructor(x: bigint) { super(); this.x = x; }\n' +
      '  public unlock() {}\n' +
      '}\n';
    // parse() does not throw on syntactic errors; it returns errors in the
    // ParseResult. We only assert the size guard does NOT trip.
    expect(() => parse(minimal, 'Counter.runar.ts')).not.toThrow(CanonicalJsonError);
  });
});
