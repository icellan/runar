import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { scoreMutant, score, GATES, REPO_ROOT, type Mutant } from '../run-mutation.js';

/**
 * F-172: the mutation scorecard is self-referential.
 *
 * `scoreMutant` only runs the gates a mutant *nominates* (`expectCaughtBy`),
 * so when a mutant nominates two gates and only one of them actually fires,
 * the mutant is still scored `caught: true` (one gate fired) and
 * `unexpectedSurvivor: false` — `missedExpectedGates` records the dead gate,
 * but nothing downstream ever inspects it: `main()`'s exit-code decision
 * (`card.unexpectedSurvivors.length > 0 || card.stale.length > 0`) does not,
 * and `score()`'s Scorecard exposes no bucket that does either. A nominated
 * gate can silently stop firing forever and the run keeps exiting 0.
 *
 * This test registers two synthetic gates (one that always "catches" via a
 * non-zero exit, one that never does — neither touches a real compiler file
 * or spawns a real test suite, so the test is fast and only exercises the
 * scorecard's own accounting) and a mutant that nominates both.
 */
describe('F-172: a caught mutant with a dead nominated gate must fail the run', () => {
  const fixtureRel = 'conformance/mutation/__tests__/.f172-scorecard-fixture.ts';
  const fixtureAbs = join(REPO_ROOT, fixtureRel);
  const alwaysCatches = 'f172-always-catches';
  const neverCatches = 'f172-never-catches';

  beforeEach(() => {
    writeFileSync(fixtureAbs, 'const x = 1;\n');
    GATES[alwaysCatches] = { cwd: '.', argv: ['node', '-e', 'process.exit(1)'] };
    GATES[neverCatches] = { cwd: '.', argv: ['node', '-e', 'process.exit(0)'] };
  });

  afterEach(() => {
    rmSync(fixtureAbs, { force: true });
    delete GATES[alwaysCatches];
    delete GATES[neverCatches];
  });

  const mutant: Mutant = {
    id: 'f172-partial-catch',
    file: fixtureRel,
    find: 'const x = 1;',
    replace: 'const x = 2;',
    class: 'synthetic',
    stage: 'test',
    expectCaughtBy: [alwaysCatches, neverCatches],
  };

  it('scoreMutant records the dead gate but still reports caught / not-unexpected-survivor', () => {
    const result = scoreMutant(mutant);
    expect(result.stale).toBe(false);
    expect(result.caught).toBe(true);
    expect(result.unexpectedSurvivor).toBe(false);
    expect(result.missedExpectedGates).toEqual([neverCatches]);
  });

  it('the scorecard must expose a signal that fails the run for this mutant', () => {
    const card = score([mutant]);
    // Today's main() exit-code decision, reproduced here verbatim (main() is
    // not exported — it is a thin CLI wrapper over exactly this boolean).
    // A Scorecard bucket for "caught but a nominated gate silently never
    // fired" must contribute to it; today none does.
    // `partiallyCaught` is the bucket this item adds; cast through `any` so
    // this test compiles identically before and after the fix lands (before
    // the fix the field does not exist and the cast reads `undefined`).
    const partiallyCaught = (card as unknown as { partiallyCaught?: unknown[] }).partiallyCaught;
    const failsRun =
      card.unexpectedSurvivors.length > 0 || card.stale.length > 0 || (partiallyCaught?.length ?? 0) > 0;
    expect(failsRun).toBe(true);
  });
});
