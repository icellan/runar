import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-422 — a refused Move `while` carries the SAME diagnostic text in every
 * tier. Two splits remained after N-341/N-421, both refusals in all seven
 * tiers (acceptance was never in question), differing only in wording:
 *
 *  1. A mirrored comparison with a NON-literal bound (`while (n > i)`). The
 *     reference folds it like `while (i < n)` (N-115) and refuses the bound
 *     with "Cannot determine loop bound"; the Zig tier did not know the
 *     iterator at parse time, so it left the condition unmirrored and printed
 *     the Move shape sentence instead.
 *  2. A NON-literal start whose iterator is read after the loop
 *     (`let acc = seed; while (acc < 5) {...}; assert_eq!(acc, ..)`). The
 *     reference type-checks first and says "Undefined variable 'acc'" (the
 *     loop variable is scoped to the loop); the loop-start sentence is only
 *     reached at ANF lowering, which it never gets to. Python and Zig raised
 *     the loop-start sentence from validation, ahead of the type checker.
 *
 * Proves: for each of those shapes every available tier's diagnostic contains
 * the reference's sentence (and the quoted iterator name where it has one),
 * and the shape sentence is absent; plus the controls that must keep their
 * wording (a non-literal start that is NOT read afterwards still says "Cannot
 * determine loop start" in every tier).
 * Does not prove: byte-identical diagnostics (locations and prefixes differ by
 * tier by design), nor anything about the other eight surfaces.
 */

const SHAPE = 'Move `while` must be a bounded counting loop';

const move = (body: string): string => `module W {
    use runar::types::{Int};
    struct W { target: Int, }
    public fun verify(contract: &W, seed: Int, n: Int) {
${body}
        assert_eq!(acc, contract.target);
    }
}
`;

const loop = (cond: string, step = 'i = i + 1;'): string =>
  `        let acc: Int = seed;\n        let i: Int = 0;\n        while (${cond}) {\n            acc = acc + i;\n            ${step}\n        };`;

const BOUND = 'Cannot determine loop bound at compile time';
const START = 'Cannot determine loop start at compile time';

const CASES: Array<[string, string, string]> = [
  ['mirrored > with a non-literal bound', loop('n > i'), BOUND],
  ['mirrored >= with a non-literal bound', loop('n >= i'), BOUND],
  ['plain non-literal bound (control)', loop('i < n'), BOUND],
  [
    'non-literal start, iterator read after the loop (acc)',
    `        let acc: Int = seed;\n        while (acc < 5) {\n            acc = acc + 1;\n        };`,
    "Undefined variable 'acc'",
  ],
  [
    'non-literal start, iterator read after the loop (i)',
    `        let acc: Int = 0;\n        let i: Int = n;\n        while (i < 5) {\n            acc = acc + i;\n            i = i + 1;\n        };\n        acc = acc + i;`,
    "Undefined variable 'i'",
  ],
  [
    'non-literal start, iterator not read after the loop (control)',
    `        let acc: Int = seed;\n        let i: Int = n;\n        while (i < 5) {\n            acc = acc + i;\n            i = i + 1;\n        };`,
    START,
  ],
];

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n422-'));
});
let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'W.runar.move');
  writeFileSync(p, src);
  return p;
}

describe('N-422 Move while refusal wording: seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF],
  ] as const) {
    for (const [name, body, sentence] of CASES) {
      it(`${name} (${mode}): every tier refuses with "${sentence}"`, () => {
        const file = write(move(body));
        const got: Record<string, string> = {};
        const want: Record<string, string> = {};
        for (const tier of tiers) {
          const r = judge(tier, file);
          got[tier.id] =
            r.verdict === 'rejected' && r.diag.includes(sentence) && !r.diag.includes(SHAPE)
              ? 'refused: reference wording'
              : `${r.verdict}: ${r.diag.slice(0, 200)}`;
          want[tier.id] = 'refused: reference wording';
        }
        expect(got).toEqual(want);
      }, 600_000);
    }
  }
});
