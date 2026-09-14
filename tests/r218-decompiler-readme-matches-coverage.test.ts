/**
 * R-218 (CL-GAP-064): the decompiler's ~2400-line symbolic-execution lifter
 * contributes ZERO wins — `coverage.json` records `"symexec": 0` — and the
 * README's headline "59/63, 93.7%" is stale against both
 * `coverage-baseline.json` (63/63) and the current `coverage.json` (77/82, 5
 * skipped).
 *
 * All three verified:
 *
 *     coverage.json        byte-match 77, byte-diff 0, compile-error 0,
 *                          parse-error 0, skipped 5   (82 rows)
 *     pathBreakdown        template 72, raw_script 4, assert-recognizer 1,
 *                          symexec 0
 *     coverage-baseline    byte-match 63, skipped 0
 *     README               "59 / 63 corpus entries ... (93.7%)"
 *
 * The README also described "4 holdouts ... pre-peephole-optimization
 * fixtures", and there are no holdouts at all now: byte-diff is 0, and the 5
 * skips are the naive SLH-DSA contracts, skipped by size rather than failed.
 *
 * This test derives the numbers from the artifact, so the headline cannot drift
 * from it again. It does not assert a particular coverage level — regenerating
 * the corpus is allowed to move these — only that the prose and the data agree.
 *
 * The `symexec: 0` case is a statement about the CORPUS, not a claim the code is
 * dead: the corpus is Rúnar-compiled output, which is what template matching is
 * best at. It is pinned because "the decompiler handles this" and "the template
 * database happens to contain this" are different guarantees, and a reader of
 * the README should be able to tell which one the number describes.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

interface Coverage {
  summary: Record<string, number>;
  pathBreakdown: Record<string, number>;
  rows: { outcome: string }[];
}

const coverage = JSON.parse(
  readFileSync(join(ROOT, 'packages/decompiler/coverage.json'), 'utf-8'),
) as Coverage;
const readme = readFileSync(join(ROOT, 'packages/decompiler/README.md'), 'utf-8');

describe('R-218: the decompiler README agrees with coverage.json', () => {
  it('the artifact has the shape this test reads', () => {
    // Anti-vacuity: a renamed field would make every assertion below pass by
    // comparing undefined to undefined.
    expect(Object.keys(coverage.summary)).toContain('byte-match');
    expect(Object.keys(coverage.pathBreakdown).length).toBeGreaterThan(1);
    expect(coverage.rows.length).toBeGreaterThan(50);
  });

  it('the headline counts come from the artifact, not from memory', () => {
    const matched = coverage.summary['byte-match']!;
    const total = coverage.rows.length;
    expect(
      readme,
      `README does not state the current byte-match count (${matched})`,
    ).toContain(String(matched));
    expect(readme, `README does not state the current corpus size (${total})`).toContain(
      String(total),
    );
  });

  it('and the stale headline is gone', () => {
    expect(readme, 'the README still claims 59 / 63').not.toMatch(/59\s*\/\s*63/);
    expect(readme, 'the README still claims 93.7%').not.toContain('93.7%');
  });

  it('the symexec contribution is stated wherever it is', () => {
    const symexec = coverage.pathBreakdown['symexec'];
    if (symexec === undefined) return; // path retired; nothing to state
    expect(
      readme,
      'the README does not say what the symbolic-execution lifter recovers',
    ).toMatch(/symexec/);
    if (symexec === 0) {
      // The finding's point: a reader must be able to learn this from the
      // README rather than by opening the JSON.
      expect(
        readme,
        'symexec recovers nothing and the README does not say so',
      ).toMatch(/symexec\D{0,80}\*\*0\*\*|contributes nothing|credited with 0/);
    }
  });

  it('no entry is failing, so "holdouts" would be wrong to claim', () => {
    // If this ever stops holding, the README's wording has to change with it —
    // which is the drift this test exists to prevent.
    for (const key of ['byte-diff', 'compile-error', 'parse-error']) {
      expect(coverage.summary[key], `${key} is no longer 0`).toBe(0);
    }
    expect(readme, 'the README still describes holdouts, but nothing is failing').not.toMatch(
      /\b4 holdouts\b/,
    );
  });
});
