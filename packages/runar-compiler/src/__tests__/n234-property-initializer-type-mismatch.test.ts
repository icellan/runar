import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-234 — a property initializer of the wrong LITERAL FAMILY compiled
 * without complaint, both for a scalar property and for a FixedArray
 * element.
 *
 * 02-validate only checked that an initializer IS a literal (bigint,
 * boolean, or ByteString, in any of their surface spellings); it never
 * checked that the literal's family matches the property's DECLARED type.
 * `readonly x: bigint = 'ab'` (a bare hex-looking string, which the parser
 * reads as a ByteString literal) and `readonly x: bigint =
 * toByteString('ab')` both passed every tier and emitted a locking script
 * that pushes a 1-byte BYTE STRING where the contract's own arithmetic
 * (`this.x === 1n`) expects a script NUMBER — a different program from the
 * one the author wrote, deployed without a word of complaint. All seven
 * tiers agreed on the wrong answer: `01ab519c`.
 *
 * The FixedArray case has a second, narrower defect on top of the same
 * root cause: N-133 already added an element-type check for FixedArray
 * initializers (03b-expand-fixed-arrays' `familyOfLiteral`), but it only
 * recognised the bare `bytestring_literal` AST node, not the
 * `toByteString(<hex>)` CALL shape that 02-validate's own
 * `isToByteStringLiteral` treats as the same ByteStringLiteral production.
 * `FixedArray<bigint, 2> = [toByteString('ab'), 0n]` slipped past N-133's
 * check for that reason alone — a bare `'ab'` element (no call wrapper) was
 * already caught.
 *
 * This test proves: both shapes are now refused, with the same wording the
 * sibling checks already use (`variable_decl` / `assignment` for the scalar
 * case, N-133's own message for the array case). It does NOT prove
 * anything about any tier but TypeScript (see the cross-tier rejection-parity
 * fixtures `conformance/negatives/N233-*` / `N234-*`, which are the 7-tier
 * gate for this exact shape), and it does not prove anything about a
 * mismatch caught anywhere other than a property initializer — the method-
 * body assignment path (`y = toByteString('ab')` for a `let y: bigint`) was
 * already refused before this change, by the pre-existing `assignment`
 * statement check.
 */

const scalarContract = (initializer: string) => `import { SmartContract, assert } from 'runar-lang';

export class BadScalarInit extends SmartContract {
  readonly x: bigint = ${initializer};

  constructor() {
    super();
  }

  public check(): void {
    assert(this.x === 1n);
  }
}
`;

const arrayContract = (initializer: string) => `import { SmartContract, assert, FixedArray } from 'runar-lang';

export class BadArrayInit extends SmartContract {
  readonly arr: FixedArray<bigint, 2> = ${initializer};

  constructor() {
    super();
  }

  public check(): void {
    assert(this.arr[0] === 1n);
  }
}
`;

describe('N-234 property initializer literal-family mismatch', () => {
  it('rejects a bare ByteString literal initializing a bigint property', () => {
    const r = compile(scalarContract("'ab'"), { fileName: 'BadScalarInit.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Type 'ByteString' is not assignable to type 'bigint'",
    );
  });

  it('rejects a toByteString(...)-wrapped literal initializing a bigint property', () => {
    const r = compile(scalarContract("toByteString('ab')"), { fileName: 'BadScalarInit.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Type 'ByteString' is not assignable to type 'bigint'",
    );
  });

  it('still accepts a well-typed scalar initializer', () => {
    expect(compile(scalarContract('1n'), { fileName: 'BadScalarInit.runar.ts' }).success).toBe(true);
  });

  it('rejects a toByteString(...)-wrapped element in a bigint FixedArray initializer', () => {
    const r = compile(arrayContract("[toByteString('ab'), 0n]"), { fileName: 'BadArrayInit.runar.ts' });
    expect(r.success).toBe(false);
    expect(r.diagnostics.map((d) => d.message).join('\n')).toContain(
      "Property 'arr' initializer element 0 is a ByteString literal, but the FixedArray element type is 'bigint'",
    );
  });

  it('still accepts a well-typed FixedArray initializer', () => {
    expect(compile(arrayContract('[0n, 0n]'), { fileName: 'BadArrayInit.runar.ts' }).success).toBe(true);
  });
});
