import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-133 — a FixedArray property initializer accepted elements of the wrong type.
 *
 * Found while building the R-101 diagnostic-coverage corpus: the element-type
 * check in 03-typecheck lives on the `array_literal` branch of inferExprType,
 * and a PROPERTY INITIALIZER never reaches it — initializers are consumed by
 * 03b-expand-fixed-arrays, which validated only the LENGTH.
 *
 * This is not cosmetic. All seven tiers accepted
 *
 *     readonly arr: FixedArray<bigint, 2> = [1n, true];
 *
 * and emitted `5151937ca0` (OP_1 OP_1 OP_ADD …) — the boolean silently became
 * the number 1. With a hex literal in the same slot the emitted script pushes a
 * BYTE STRING where the contract's own arithmetic expects a number
 * (`5102aabb937ca0`), so `this.arr[0n] + this.arr[1n]` is an OP_ADD over a
 * 2-byte blob: a different program from the one the author wrote, deployed
 * without a word of complaint.
 *
 * The length check next to it was already there and already ported to all
 * seven tiers, so the element check goes in the same place, with a message all
 * seven emit verbatim.
 */

const contract = (declared: string, initializer: string, extraImports = '') => `import { SmartContract, assert, FixedArray${extraImports} } from 'runar-lang';

export class Neg extends SmartContract {
  readonly arr: ${declared} = ${initializer};

  constructor() {
    super();
  }

  public go(x: bigint) {
    assert(x > 0n);
  }
}
`;

function compileIt(declared: string, initializer: string, extraImports = '') {
  return compile(contract(declared, initializer, extraImports), { fileName: 'Neg.runar.ts' });
}

describe('N-133 FixedArray initializer element types', () => {
  it('rejects a boolean in a bigint array', () => {
    const r = compileIt('FixedArray<bigint, 2>', '[1n, true]');
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Property 'arr' initializer element 1 is a boolean literal, but the FixedArray element type is 'bigint'",
    );
  });

  it('rejects a hex literal in a bigint array', () => {
    const r = compileIt('FixedArray<bigint, 2>', "[1n, 'aabb']");
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Property 'arr' initializer element 1 is a ByteString literal, but the FixedArray element type is 'bigint'",
    );
  });

  it('rejects a number in a ByteString array', () => {
    const r = compileIt('FixedArray<ByteString, 2>', "['aa', 1n]", ', ByteString');
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Property 'arr' initializer element 1 is a bigint literal, but the FixedArray element type is 'ByteString'",
    );
  });

  it('reports EVERY bad element, not just the first', () => {
    const r = compileIt('FixedArray<bigint, 3>', "[true, 'aa', 2n]");
    const msgs = r.diagnostics.map((d) => d.message).filter((m) => m.includes('initializer element'));
    expect(msgs.length).toBe(2);
    expect(msgs[0]).toContain('element 0');
    expect(msgs[1]).toContain('element 1');
  });

  it('still accepts a well-typed initializer, in every family', () => {
    expect(compileIt('FixedArray<bigint, 2>', '[1n, 2n]').success).toBe(true);
    expect(compileIt('FixedArray<ByteString, 2>', "['aa', 'bb']", ', ByteString').success).toBe(true);
    expect(compileIt('FixedArray<boolean, 2>', '[true, false]').success).toBe(true);
    // Subtypes of the ByteString family accept a hex literal.
    expect(compileIt('FixedArray<Sha256, 1>', "['" + 'ab'.repeat(32) + "']", ', Sha256').success).toBe(true);
    // A bigint-family subtype accepts a numeric literal.
    expect(compileIt('FixedArray<RabinSig, 1>', '[7n]', ', RabinSig').success).toBe(true);
  });

  it('still accepts a well-typed NESTED initializer', () => {
    const r = compileIt('FixedArray<FixedArray<bigint, 2>, 2>', '[[1n, 2n], [3n, 4n]]');
    expect(r.diagnostics.map((d) => d.message)).toEqual([]);
    expect(r.success).toBe(true);
  });

  it('rejects a bad element nested one level down', () => {
    const r = compileIt('FixedArray<FixedArray<bigint, 2>, 2>', '[[1n, 2n], [3n, true]]');
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain('is a boolean literal');
  });
});
