import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadMutants, REPO_ROOT } from '../run-mutation.js';

/**
 * F-252: `conformance/mutation/README.md` stated a hardcoded mutant count
 * ("`mutants.json` has 22 mutants") that drifted from reality once the
 * 2026-08-17 frame-offset family (`ef753a8f6`) added six more mutants without
 * updating the prose. `mutants.json` has 28 entries; the README said 22.
 *
 * This test derives the expected count from `mutants.json` itself via
 * `loadMutants()` rather than hardcoding either number, so it stays green
 * through future corpus growth and only fails when the README's stated count
 * next drifts from the corpus it describes.
 *
 * What this proves: the README's stated mutant count is kept in sync with
 * the actual corpus size.
 * What this does NOT prove: that the README's prose describing the mutant
 * *groups* (which files/classes they cover) is accurate — only the headline
 * count is checked mechanically here.
 */
describe('F-252: mutation README mutant count matches mutants.json', () => {
  const readmePath = join(REPO_ROOT, 'conformance', 'mutation', 'README.md');
  const readme = readFileSync(readmePath, 'utf8');

  it('the README states a count, and it equals loadMutants().length', () => {
    const match = readme.match(/`mutants\.json` has (\d+) mutants/);
    expect(match).not.toBeNull();
    const statedCount = Number(match![1]);
    expect(statedCount).toBe(loadMutants().length);
  });
});
