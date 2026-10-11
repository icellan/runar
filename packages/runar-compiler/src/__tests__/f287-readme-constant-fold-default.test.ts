/**
 * F-287 (GK-DOC-001) — `packages/runar-compiler/README.md` claimed constant
 * folding is "disabled by default to preserve ANF conformance", but
 * `compile()`'s `disableConstantFolding` option defaults to `false`, which
 * means folding RUNS by default (see `index.ts`, Pass 4.25: "Constant folding
 * (on by default)"). CI's checked-in goldens are fold-OFF only because the
 * conformance runner explicitly passes `--disable-constant-folding`; a
 * consumer who calls `compile()` with default options — following only the
 * README — gets fold-ON bytes and will not reproduce those goldens. The same
 * wrong claim was copy-pasted into `docs/compiler-architecture.md` and
 * `docs/java-tier-plan.md`.
 *
 * What this proves:
 *   1. Behaviour: `compile()` with default options (no `disableConstantFolding`)
 *      folds a constant-foldable expression — its emitted script differs from
 *      the explicit fold-OFF run — so "disabled by default" is factually false
 *      for the documented public API.
 *   2. Documentation: none of the three docs state or imply that folding is
 *      off/disabled by default; each says (or no longer contradicts) that it
 *      is on by default and that conformance tooling opts out of it.
 *
 * What this does NOT prove:
 *   - Anything about `compileFromANF` (that entry point ignores the flag
 *     entirely and is covered separately by F-002/f002-compile-from-anf-fold-
 *     option.test.ts).
 *   - That the fold-ON output is the "right" default architecturally — only
 *     that the docs must describe the default that actually ships.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile } from '../index.js';

const REPO = resolve(__dirname, '../../../..');
const read = (rel: string) => readFileSync(resolve(REPO, rel), 'utf-8');

/** unlock() { assert((2n + 3n) === 5n) } — `2n + 3n` is foldable. */
const FOLDABLE_SOURCE = `
import { SmartContract, assert } from 'runar-lang';

export class Foldable extends SmartContract {
  readonly tag: bigint;
  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }
  public unlock(): void {
    assert((2n + 3n) === 5n);
  }
}
`;

describe('F-287 constant folding is ON by default; the docs must say so', () => {
  it('compile() with default options folds, diverging from the explicit fold-OFF script', () => {
    const byDefault = compile(FOLDABLE_SOURCE, { fileName: 'Foldable.runar.ts' });
    const foldOff = compile(FOLDABLE_SOURCE, {
      fileName: 'Foldable.runar.ts',
      disableConstantFolding: true,
    });

    expect(byDefault.success, byDefault.diagnostics.map((d) => d.message).join('; ')).toBe(true);
    expect(foldOff.success, foldOff.diagnostics.map((d) => d.message).join('; ')).toBe(true);

    // If folding were truly disabled by default (as the README claimed),
    // these two scripts would be byte-identical.
    expect(byDefault.artifact?.script).not.toBe(foldOff.artifact?.script);
  });

  /**
   * A paragraph-scoped check for the literal wrong phrasing — "disabled by
   * default" / "off by default" — attached to a fold mention, not a loose
   * character-distance regex. The literal phrase is specific: it would NOT
   * flag `runar-verification/TRUST_MANIFEST.md`'s correct statement ("the
   * checked-in goldens ... are stamped under constant-folding OFF. The real
   * compilers ship folding ON by default."), which says "ON by default" and
   * "constant-folding OFF" as two separate clauses, never "off by default" —
   * but that file isn't part of this sweep anyway. It also doesn't flag this
   * file's own corrected wording ("turned off with `disableConstantFolding`",
   * "generated with it off"), since neither puts "disabled"/"off" directly
   * before "by default".
   */
  function paragraphsWrongAboutFoldDefault(text: string): string[] {
    return text
      .split(/\n\s*\n/)
      .filter((p) => /\bfold/i.test(p) && /\b(?:disabled|off)\s+by\s+default\b/i.test(p));
  }

  for (const doc of [
    'packages/runar-compiler/README.md',
    'docs/compiler-architecture.md',
    'docs/java-tier-plan.md',
  ]) {
    it(`${doc} does not claim constant folding is disabled/off by default`, () => {
      const text = read(doc);
      const bad = paragraphsWrongAboutFoldDefault(text);
      expect(
        bad,
        `${doc} still has a paragraph stating constant folding is disabled/off ` +
          `by default, contradicting index.ts's actual default (folding runs ` +
          `unless disableConstantFolding is explicitly set):\n${bad.join('\n---\n')}`,
      ).toEqual([]);
    });
  }
});
