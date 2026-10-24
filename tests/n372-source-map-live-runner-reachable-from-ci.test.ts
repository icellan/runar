/**
 * N-372: the LIVE source-map runner (conformance/source-map/run.ts) must be
 * invoked by a CI step, and mirrored in a ci-local script chained into
 * `test:ci-local`.
 *
 * The vitest step over `conformance/source-map` only collects the *.test.ts
 * files there (golden-only checks). run.ts is what compiles every
 * (fixture, tier) pair live and applies the structural, anchor (N-370) and
 * whole-map shape rules, so without its own step a regression in a live
 * compile that was never re-stamped into a golden is invisible to CI.
 *
 * run.ts reports an unavailable tier as a SKIP row and still exits 0, so the
 * step must also refuse any SKIP row, or a job missing a compiler binary
 * would pass vacuously.
 *
 * Proves: a non-comment workflow line runs `conformance/source-map/run.ts`,
 * that line (or its step) rejects SKIP rows, and package.json has a
 * ci-local script doing the same that `test:ci-local` chains. Does not prove:
 * that the runner passes, that the step's job executes, or that the job has
 * all seven tiers built (the step sits in the `conformance` job, which
 * `needs` all seven compiler jobs).
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RUNNER = /conformance\/source-map\/run\.ts/;

function workflowLines(): string[] {
  const dir = join(ROOT, '.github', 'workflows');
  const out: string[] = [];
  for (const f of readdirSync(dir)) {
    if (!/\.ya?ml$/.test(f)) continue;
    for (const line of readFileSync(join(dir, f), 'utf8').split('\n')) {
      if (!/^\s*#/.test(line)) out.push(line);
    }
  }
  return out;
}

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as {
  scripts: Record<string, string>;
};

describe('N-372: live source-map runner is invoked by CI', () => {
  it('a workflow runs conformance/source-map/run.ts and rejects SKIP rows', () => {
    const hits = workflowLines().filter((l) => RUNNER.test(l));
    expect(hits, 'no non-comment workflow line runs conformance/source-map/run.ts').not.toEqual([]);
    expect(
      hits.some((l) => /SKIP/.test(l)),
      'the run.ts step must fail on a SKIP (tier not available) row',
    ).toBe(true);
  });

  it('a ci-local script runs it and test:ci-local chains that script', () => {
    const names = Object.entries(pkg.scripts)
      .filter(([n, c]) => n.startsWith('ci-local:') && RUNNER.test(c))
      .map(([n]) => n);
    expect(names, 'no ci-local script runs conformance/source-map/run.ts').not.toEqual([]);
    const chain = pkg.scripts['test:ci-local']!;
    for (const n of names) expect(chain).toContain(`pnpm run ${n} `);
    expect(names.some((n) => /SKIP/.test(pkg.scripts[n]!))).toBe(true);
  });
});
