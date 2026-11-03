import { describe, it, expect } from 'vitest';
import { loadMutants } from '../run-mutation.js';

/**
 * N-287: the mutation corpus had no mutant on `peephole.ts`'s nested-IR walk /
 * emission logic (the N-264 bottom-up if-arm walk in `optimizeStackIR` /
 * `withOptimizedArms`, or F-392's opcode-string-form rule matching in
 * `applyOnePass`'s rule table) or on `passes/side-effect-summary.ts`'s
 * private-method call-graph walk. Every existing peephole mutant in
 * `mutants.json` targets only the declarative mirror in `peephole-rules.ts`
 * (see README.md's "Gates" / "Corpus shape" sections) — a documentation-only
 * table that `optimizeStackIR` does not import or consult, so it structurally
 * cannot measure a defect in the real engine.
 *
 * What this proves: the corpus contains at least one mutant whose `file` is
 * the real engine file for each of the two named surfaces, so the
 * measured-detection-power claim this harness exists to make (TS-GAP-006)
 * actually covers them.
 * What this does NOT prove: that any particular gate catches these mutants —
 * see `baseline.json` and each mutant's `finding`/`checkGates` for the
 * measured (not assumed) result of running them.
 */
describe('N-287: mutation corpus covers peephole.ts walk logic and side-effect-summary.ts', () => {
  const mutants = loadMutants();

  it('has at least one mutant on peephole.ts itself (not just the declarative peephole-rules.ts mirror)', () => {
    const peepholeEngineMutants = mutants.filter(
      (m) => m.file === 'packages/runar-compiler/src/optimizer/peephole.ts',
    );
    expect(peepholeEngineMutants.length).toBeGreaterThan(0);
  });

  it('has at least one mutant on passes/side-effect-summary.ts', () => {
    const sideEffectMutants = mutants.filter(
      (m) => m.file === 'packages/runar-compiler/src/passes/side-effect-summary.ts',
    );
    expect(sideEffectMutants.length).toBeGreaterThan(0);
  });
});
