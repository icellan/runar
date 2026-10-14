import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-244 — the non-TS half of N-039. `@sighash` is honoured only on the
 * `.runar.ts` surface; the eight other surfaces refuse it because their
 * parsers drop comments. Before this item every tier scanned for the marker
 * with a word boundary (`@sighash\b`), so `@sighashSINGLE|FORKID` slipped past
 * the guard and the method compiled under the default ALL|FORKID — the same
 * hole N-039 closed on `.runar.ts`. The refusal text also differed per tier
 * (Zig, Ruby and Java each had their own).
 *
 * N-093: those surfaces now spell the directive natively (a modifier, not a
 * comment), so the shared refusal for a COMMENT directive names that spelling.
 *
 * What this proves:
 *   - for each of the eight non-TS surfaces, every tier refuses a glued
 *     `@sighashSINGLE|FORKID` comment AND a well-formed `@sighash SINGLE|FORKID`
 *     comment, and the diagnostic carries the ONE shared message
 *     `@sighash directive (issue #123) is not supported by the <Surface>
 *     surface parser; ...` with the same surface name in all seven tiers;
 *   - every fixture is otherwise valid: with the marker replaced by plain
 *     prose, all seven tiers accept it and emit the same hex, so the refusal
 *     is the guard's and nothing else's;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - anything about `.runar.ts`, which honours the directive (N-039 gates the
 *     glued form there);
 *   - anything about `@embedAlways`, whose guard is untouched by this item;
 *   - where the guard sits in each tier's pipeline beyond "before a script is
 *     emitted": the CLIs expose only the final verdict and diagnostic.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const GLUED = '@sighashSINGLE|FORKID';

const FIXTURES: ReadonlyArray<readonly [string, string]> = [
  ['N245-sol-sighash-glued.runar.sol', 'Solidity'],
  ['N246-move-sighash-glued.runar.move', 'Move'],
  ['N247-py-sighash-glued.runar.py', 'Python'],
  ['N248-go-sighash-glued.runar.go', 'Go DSL'],
  ['N249-rs-sighash-glued.runar.rs', 'Rust'],
  ['N250-zig-sighash-glued.runar.zig', 'Zig'],
  ['N251-rb-sighash-glued.runar.rb', 'Ruby'],
  ['N252-java-sighash-glued.runar.java', 'Java'],
];

// N-093: the refusal names the surface's native spelling of the directive.
const NATIVE: Record<string, [doc: string, sighash: string, embed: string]> = {
  Solidity: ['solidity', 'the function modifier sighash(<FLAGS>)', 'the property modifier embedAlways'],
  Move: ['move', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
  Python: ['python', '@public(sighash="<FLAGS>")', 'the wrapper type EmbedAlways[T]'],
  'Go DSL': ['go', 'the directive //runar:sighash <FLAGS>', 'the struct tag option runar:"readonly,embedAlways"'],
  Rust: ['rust', 'the attribute #[sighash(<FLAGS>)]', 'the attribute #[embed_always]'],
  Zig: ['zig', 'the return type runar.Sighash("<FLAGS>")', 'the type function runar.EmbedAlways(T)'],
  Ruby: ['ruby', "runar_sighash '<FLAGS>'", 'the prop option embed_always: true'],
  Java: ['java', 'the annotation @Sighash("<FLAGS>")', 'the annotation @EmbedAlways'],
};

const message = (surface: string): string =>
  `@sighash directive (issue #123) is not supported as a comment by the ${surface} surface parser; write it as ${NATIVE[surface]![1]} (see docs/formats/${NATIVE[surface]![0]}.md)`;

/** The fixture with its glued marker replaced, written under its own file name
 *  (the extension selects the surface) in a fresh temp directory. */
function variant(fixture: string, replacement: string): string {
  const text = readFileSync(join(DIR, fixture), 'utf8');
  if (text.split(GLUED).length !== 2) throw new Error(`${fixture}: expected exactly one '${GLUED}'`);
  const dir = mkdtempSync(join(tmpdir(), 'n244-'));
  const out = join(dir, basename(fixture));
  writeFileSync(out, text.replace(GLUED, replacement));
  return out;
}

/** The hex a tier printed: the last stdout/stderr line that is pure hex. */
function hexOf(diag: string): string {
  const lines = diag.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]+$/.test(l));
  return lines[lines.length - 1] ?? `<no hex in: ${diag.slice(0, 200)}>`;
}

describe('N-244: every tier refuses a @sighash marker on every non-TS surface, with one message', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, surface] of FIXTURES) {
    for (const [label, path] of [
      ['glued', () => join(DIR, fixture)],
      ['spaced', () => variant(fixture, '@sighash SINGLE|FORKID')],
    ] as const) {
      it(`${fixture} (${label}) -> ${message(surface).slice(0, 80)}...`, () => {
        const src = path();
        const got: Record<string, string> = {};
        for (const tier of TIERS) {
          const r = judge(tier, src);
          got[tier.id] =
            r.verdict === 'rejected' && r.diag.includes(message(surface))
              ? 'shared diagnostic'
              : `${r.verdict}: ${r.diag.trim().slice(0, 300)}`;
        }
        expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
      }, 900_000);
    }

    it(`${fixture} with the marker replaced by prose compiles to the same hex in every tier`, () => {
      const src = variant(fixture, 'Bump the counter.');
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, src);
        got[tier.id] = r.verdict === 'accepted' ? hexOf(r.diag) : `rejected: ${r.diag.trim().slice(0, 300)}`;
      }
      const reference = got.ts!;
      expect(reference).toMatch(/^[0-9a-f]+$/);
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, reference])));
    }, 900_000);
  }
});
