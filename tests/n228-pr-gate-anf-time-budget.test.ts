/**
 * N-228 — the PR-gate `--anf` fuzz steps in `fuzzer-nightly.yml` pass no
 * `--time-budget-ms`, so F-173's delta-debugging shrinker
 * (`anf-differential.ts`'s `shrink`) runs with `deadline === undefined` on a
 * failing PR run: `(deadline === undefined || Date.now() <= deadline)` is
 * always true, so `reduceAnfProgram` keeps trying candidates with no wall-clock
 * cap. The nightly `--anf` step (same workflow) already resolves a budget via
 * `Resolve fuzz parameters` and passes `--time-budget-ms "$BUDGET"`; the two
 * PR-gate `--anf` steps (fold-OFF / fold-ON, fixed seed 424242) never got the
 * same treatment.
 *
 * This test reads the workflow as text (no YAML parser among the root deps,
 * matching the sibling F-053 test's approach) and asserts every step that
 * invokes the fuzzer in `--anf` mode also passes `--time-budget-ms`.
 *
 * What it proves: the workflow text, as committed, gives every `--anf`
 * invocation a wall-clock budget argument.
 * What it does not prove: that GitHub Actions actually runs the step this
 * way, that the budget value chosen is well-tuned, or anything about the
 * shrinker's runtime behavior (see `anf-differential.test.ts` for that).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(__dirname, '..');
const read = (rel: string) => readFileSync(join(REPO, rel), 'utf-8');

/** Drop full-line comments so a prose mention of "--anf" cannot match. */
const codeLines = (text: string) => text.split('\n').filter((l) => !/^\s*#/.test(l));

describe('N-228: every --anf fuzz step carries a time budget', () => {
  it('each --anf invocation in fuzzer-nightly.yml passes --time-budget-ms', () => {
    const yml = codeLines(read('.github/workflows/fuzzer-nightly.yml')).join('\n');
    const blocks = yml.split(/\n      - name: /).filter((b) => /--anf\b/.test(b));

    // Nightly (resolved-budget) + PR-gate fold-OFF + PR-gate fold-ON == 3.
    // A future step added/renamed must still show up here, not vanish.
    expect(blocks.length, 'expected at least 3 --anf steps (nightly + 2 PR-gate)').toBeGreaterThanOrEqual(3);

    const offenders: string[] = [];
    for (const block of blocks) {
      const name = block.split('\n')[0]!.trim();
      // Literal integer (PR gate) or a shell variable expansion (nightly,
      // resolved from a prior step's output), optionally quoted.
      if (!/--time-budget-ms[ \t\\\n]+("?\$[A-Z_]+"?|\d+)/.test(block)) {
        offenders.push(name);
      }
    }
    expect(
      offenders,
      'an --anf step with no --time-budget-ms lets F-173\'s shrinker run unbounded on a failing run',
    ).toEqual([]);
  });
});
