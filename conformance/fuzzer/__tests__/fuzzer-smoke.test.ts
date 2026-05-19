/**
 * Item 7 smoke test — runs the ANF differential fuzzer with a small
 * program count (5) and asserts no cross-tier hex divergence.
 *
 * The fuzzer itself is the real test; this file exists to:
 *  (1) make the fuzzer infrastructure runnable from `pnpm vitest run
 *      fuzzer` so it lands in the standard test matrix and breaks CI on
 *      regression, and
 *  (2) act as a guard against accidental fuzzer-harness breakage (e.g.
 *      a renamed CLI flag on a tier compiler, a broken `loadANFFromJSON`
 *      contract change, or a missing canonicalJsonStringify export).
 *
 * Tier availability: only tiers whose binary is on disk participate.
 * The smoke test ALWAYS exercises the TS in-process path (which doesn't
 * need a binary), so it's a meaningful gate even on a developer laptop
 * with no Go / Rust / Zig builds. On CI, the fuzzer-nightly workflow
 * builds all 7 tiers before invoking this so the full matrix runs.
 */

import { describe, it, expect } from 'vitest';
import { runAnfDifferential, ALL_TIERS } from '../anf-differential.js';

describe('ANF differential fuzzer (Item 7 smoke)', () => {
  it('5 random programs × every available tier produce identical hex', async () => {
    const report = await runAnfDifferential({
      numPrograms: 5,
      seed: 1337,
      tiers: ALL_TIERS,
      // Generous time budget; the smoke test wants to actually complete
      // its 5 programs, not race a wall-clock. CI's nightly workflow
      // uses the harness's own --time-budget-ms flag for the larger run.
      timeBudgetMs: 120_000,
      verbose: false,
    });

    // ---------------------------------------------------------------------
    // Sanity: the harness must actually run all 5 programs (so we know
    // the generator + canonicalJSON + at least one loader path is wired).
    // ---------------------------------------------------------------------
    expect(report.totalPrograms).toBe(5);
    expect(report.programsRun).toBe(5);

    // ---------------------------------------------------------------------
    // At least TS must be available (it's in-process; no binary required).
    // If TS is missing, something is structurally wrong with the
    // workspace bootstrap path that the fuzzer relies on.
    // ---------------------------------------------------------------------
    expect(report.perTierAvailable.ts).toBe(true);

    // ---------------------------------------------------------------------
    // The real assertion: any tier that produced output must agree with
    // every other tier on every program. A non-zero mismatch count
    // means a real cross-tier conformance regression that needs
    // investigation (the per-finding directory under
    // conformance/fuzz-findings-anf/ has the reproducing program + the
    // diverging hex outputs).
    // ---------------------------------------------------------------------
    expect(report.mismatchCount, mismatchMessage(report.findings)).toBe(0);

    // Smoke test should never time out — flag if it does so we can
    // either raise the budget or investigate compiler perf regressions.
    expect(report.earlyStop).toBe(false);
  }, 180_000);
});

function mismatchMessage(findings: string[]): string {
  if (findings.length === 0) return 'cross-tier hex mismatch';
  return `cross-tier hex mismatch — see ${findings[0]} (${findings.length} finding(s) total)`;
}
