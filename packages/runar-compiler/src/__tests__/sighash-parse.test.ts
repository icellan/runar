import { describe, it, expect } from 'vitest';
import { parse } from '../passes/01-parse.js';

function methodByName(src: string, name: string) {
  const r = parse(src, 'X.runar.ts');
  expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
  return r.contract!.methods.find((m) => m.name === name)!;
}

describe('#123 @sighash directive parsing (TS surface)', () => {
  it('sets sighashType from a JSDoc directive on a public method', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(methodByName(src, 'bump').sighashType).toBe(0x43);
  });

  it('leaves sighashType undefined when there is no directive (default 0x41)', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }`;
    expect(methodByName(src, 'bump').sighashType).toBeUndefined();
  });

  it('accepts a // line-comment directive', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        // @sighash NONE|FORKID
        public wipe(): void { this.n = 0n; }
      }`;
    expect(methodByName(src, 'wipe').sighashType).toBe(0x42);
  });

  it('reports an error for a bad flag combo', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash ALL|NONE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`;
    const r = parse(src, 'X.runar.ts');
    expect(r.errors.some((e) => /cannot combine base types/.test(e.message))).toBe(true);
  });

  it('reports an error for @sighash on a private method', () => {
    const src = `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        private helper(): bigint { return 1n; }
        public bump(): void { this.n = this.n + 1n; }
      }`;
    const r = parse(src, 'X.runar.ts');
    expect(r.errors.some((e) => /non-public method/.test(e.message))).toBe(true);
  });
});

// F-039 — a `@sighash` marker that is present but is not followed by a
// well-formed flag list used to be treated as "no directive": the method
// silently compiled under the default ALL|FORKID, a materially different
// covenant from the one the author declared (e.g. a trailing `!` typo on
// `@sighash SINGLE|FORKID!`). A second directive on the same method was
// silently ignored (and which one won differed across tiers). Both are now
// compile errors carrying one shared diagnostic in all seven tiers.
//
// Proves: the TS parser refuses each malformed/ambiguous shape with the shared
// text, and still honours the well-formed control and the reference's
// word-boundary rule (`@sighashSINGLE` / `@sighashType` are NOT markers).
// Does not prove: the other six tiers agree — that is the rejection-parity
// gate (conformance/negatives/N95..N98) plus each tier's own unit test.
describe('F-039 malformed @sighash directive is fail-closed (TS surface)', () => {
  const MALFORMED =
    "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)";
  const MULTIPLE =
    "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one";

  const withLeading = (leading: string) => `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        ${leading}
        public bump(): void { this.addOutput(1000n, this.n); }
      }`;

  const errorsOf = (src: string) =>
    parse(src, 'X.runar.ts').errors.filter((e) => e.severity === 'error').map((e) => e.message);

  it.each([
    ['trailing punctuation', '/** @sighash SINGLE|FORKID! */'],
    ['colon instead of whitespace', '/** @sighash:SINGLE|FORKID */'],
    ['equals instead of whitespace', '// @sighash=SINGLE|FORKID'],
    ['comma separator', '/** @sighash SINGLE,FORKID */'],
  ])('rejects %s with the shared malformed diagnostic', (_label, leading) => {
    expect(errorsOf(withLeading(leading))).toEqual([MALFORMED]);
  });

  it('rejects a bare marker with no flag list (line comment)', () => {
    expect(errorsOf(withLeading('// @sighash'))).toEqual([
      "Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)",
    ]);
  });

  it.each([
    ['two directives in one block', '/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */'],
    ['two directive blocks', '/** @sighash SINGLE|FORKID */\n  /** @sighash ALL|FORKID */'],
    ['malformed then well-formed', '/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */'],
  ])('rejects %s with the shared multiple-directive diagnostic', (_label, leading) => {
    expect(errorsOf(withLeading(leading))).toEqual([MULTIPLE]);
  });

  it('keeps the reference word boundary: `@sighashSINGLE` / `@sighashType` are not markers', () => {
    for (const leading of ['/** @sighashSINGLE|FORKID */', '/** see the @sighashType docs */']) {
      const r = parse(withLeading(leading), 'X.runar.ts');
      expect(r.errors.filter((e) => e.severity === 'error')).toEqual([]);
      expect(r.contract!.methods.find((m) => m.name === 'bump')!.sighashType).toBeUndefined();
    }
  });

  it('still honours a well-formed multi-line JSDoc directive', () => {
    expect(
      methodByName(withLeading('/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */'), 'bump').sighashType,
    ).toBe(0x43);
  });
});
