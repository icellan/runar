import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-121 (user decision R85) — optional chaining is refused by every tier,
 * with ONE diagnostic.
 *
 * spec/grammar.md lists optional chaining (`?.`) as disallowed. Before this
 * item the TS reference and the Go tier compiled `this?.t` as `this.t`,
 * `this.a?.[0]` as `this.a[0]`, and `this?.check(x)` / `this.check?.(x)` as
 * plain calls, while Rust, Python, Zig, Ruby and Java refused all four, each
 * in its own words.
 *
 * What this proves:
 *   - every tier refuses the four `?.` shapes (property, method call,
 *     optional call, index) with `<file>:<line>:<col>: optional chaining '?.' is not
 *     supported`, where the column is the 0-based position (N-078, R88a) of
 *     the `?`, computed from the fixture text, never copied from a compiler;
 *   - every tier still ACCEPTS a `?` ternary written without spaces before a
 *     `this.` operand, and a `?.` inside a line and a block comment, so the
 *     check is not a blind character scan;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - which diagnostics a tier prints AFTER the shared one (the hand-written
 *     tokenizers keep lexing `?` `.` and their parsers add their own errors);
 *   - more than one `?.` per file: each tier reports the first one only;
 *   - optional chaining on any surface other than `.runar.ts`.
 */

const TIERS = buildSourceTiers();
const DIR = join(REPO, 'conformance/negatives');

const OPTIONAL_CHAINING = "optional chaining '?.' is not supported";

/** [fixture, 1-based line of the `?.`]. */
const REFUSED: Array<[string, number]> = [
  ['N229-ts-optional-chaining-property.runar.ts', 17],
  ['N230-ts-optional-chaining-method-call.runar.ts', 15],
  ['N231-ts-optional-call.runar.ts', 15],
  ['N232-ts-optional-chaining-index.runar.ts', 14],
];

function expectedColumn(fixture: string, line: number): number {
  const text = readFileSync(join(DIR, fixture), 'utf8').split('\n')[line - 1] ?? '';
  const col = text.indexOf('?.');
  if (col < 0) throw new Error(`${fixture}:${line}: no '?.' on that line`);
  return col;
}

const escape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Accepted: a tight ternary, and `?.` inside a line and a block comment. */
const ACCEPTED_SOURCE = `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  // this?.t in a comment is not code
  public unlock(x: bigint) {
    const y = x > 0n?this.t:x;
    assert(y === this.t);
    /* this?.t */
  }
}
`;

describe('N-121: every tier refuses optional chaining with one diagnostic', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, line] of REFUSED) {
    it(`${fixture} -> ${fixture}:${line}:<0-based col of '?.'>: ${OPTIONAL_CHAINING}`, () => {
      const want = `${fixture}:${line}:${expectedColumn(fixture, line)}: ${OPTIONAL_CHAINING}`;
      const re = new RegExp(escape(want));
      const got: Record<string, string> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(DIR, fixture));
        got[tier.id] = r.verdict === 'rejected' && re.test(r.diag) ? 'shared diagnostic' : `${r.verdict}: ${r.diag.trim().slice(0, 200)}`;
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'shared diagnostic'])));
    }, 900_000);
  }

  it('a tight `?` ternary and `?.` in comments still compile in every tier', () => {
    const dir = mkdtempSync(join(tmpdir(), 'n121-'));
    const src = join(dir, 'Probe.runar.ts');
    writeFileSync(src, ACCEPTED_SOURCE);
    const got: Record<string, string> = {};
    for (const tier of TIERS) {
      const r = judge(tier, src);
      got[tier.id] = r.verdict === 'accepted' ? 'accepted' : `rejected: ${r.diag.trim().slice(0, 200)}`;
    }
    expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'accepted'])));
  }, 900_000);
});
