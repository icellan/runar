import { describe, it, expect } from 'vitest';
import { findBaselineRegressions, type BaselineEntry, type MutantResult } from '../run-mutation.js';

/**
 * F-251: six of the 28 mutants in `mutants.json` have no entry in
 * `baseline.json` (added in `ef753a8f6` without a `--write-baseline`
 * re-stamp). The nightly "Baseline regression check" step in
 * `.github/workflows/fuzzer-nightly.yml` used to be a bare
 * `for (const b of base)` loop: it looks up each STAMPED id in the current
 * run, but never visits a current-run mutant that has no stamped entry at
 * all — so a mutant missing from the baseline that flips from caught to
 * SURVIVES is structurally invisible to this specific gate (it would still
 * be caught by the separate "must never survive" scorecard gate, but that is
 * a different question: "is it ever caught" vs. "did it regress since the
 * last stamp").
 *
 * `findBaselineRegressions` is the extracted, testable form of that CI
 * step's comparison. This test proves it reports a baseline-less mutant
 * that currently survives, and proves it stays silent for a baseline-less
 * mutant that is currently caught (no false alarm just for being unstamped).
 *
 * What this proves: the comparison function itself now has a reverse loop
 * and behaves correctly on synthetic `base`/`cur` inputs shaped exactly like
 * `baseline.json` / `mutation-current.json`.
 * What this does NOT prove: that `.github/workflows/fuzzer-nightly.yml`'s
 * `tsx -e` step actually wires this function in at CI runtime (that edit was
 * additionally smoke-tested by hand against real `baseline.json` content —
 * see the F-251 subagent report — but is not covered by an automated test,
 * since the workflow only runs in GitHub Actions); nor does it prove
 * `baseline.json` itself has been re-stamped to include the six un-stamped
 * mutants — that still requires a full 28-mutant gate run and is explicitly
 * out of scope here.
 */
describe('F-251: findBaselineRegressions sees mutants absent from the baseline', () => {
  const unstampedSurvived: MutantResult = {
    id: 'stacklower-dup-records-undefined',
    class: 'off-by-one stack index',
    stage: 'stack-lower',
    caught: false,
    survived: true,
    caughtBy: [],
    expectCaughtBy: ['stack-frame-mutation-pins'],
    documentedSurvivor: false,
    unexpectedSurvivor: true,
    missedExpectedGates: ['stack-frame-mutation-pins'],
    stale: false,
  };

  const unstampedCaught: MutantResult = {
    ...unstampedSurvived,
    id: 'stacklower-dup-records-neighbour',
    caught: true,
    survived: false,
    caughtBy: ['stack-frame-mutation-pins'],
    unexpectedSurvivor: false,
    missedExpectedGates: [],
  };

  // `baseline.json` today has no entry for either id above — this mirrors
  // that gap directly instead of re-deriving it from the real file, so the
  // test does not depend on baseline.json's exact current contents.
  const base: BaselineEntry[] = [
    {
      id: 'stacklower-add-to-sub',
      caught: true,
      survived: false,
      expectCaughtBy: ['differential-witness'],
    },
  ];

  it('reports a baseline-less mutant that is currently surviving', () => {
    const regressions = findBaselineRegressions(base, [unstampedSurvived]);
    expect(regressions.some((r) => r.includes('stacklower-dup-records-undefined'))).toBe(true);
  });

  it('does not report a baseline-less mutant that is currently caught', () => {
    const regressions = findBaselineRegressions(base, [unstampedCaught]);
    expect(regressions.some((r) => r.includes('stacklower-dup-records-neighbour'))).toBe(false);
  });

  it('still reports a stamped mutant that regressed (forward loop unaffected)', () => {
    const regressed: MutantResult = {
      id: base[0]!.id,
      expectCaughtBy: base[0]!.expectCaughtBy,
      class: 'swapped operands',
      stage: 'stack-lower',
      caughtBy: [],
      caught: false,
      survived: true,
      documentedSurvivor: false,
      unexpectedSurvivor: true,
      missedExpectedGates: ['differential-witness'],
      stale: false,
    };
    const regressions = findBaselineRegressions(base, [regressed]);
    expect(regressions.some((r) => r.includes('stacklower-add-to-sub') && r.includes('now SURVIVES'))).toBe(
      true,
    );
  });
});
