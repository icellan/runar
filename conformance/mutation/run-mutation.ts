/**
 * Mutation-scoring harness for the Rúnar safety net (TS-GAP-006).
 *
 * Applies each curated mutant in `mutants.json` to a real compiler source file,
 * runs the mapped fast in-process gate(s), records caught-vs-survived, and
 * ALWAYS reverts (try/finally + snapshot restore) so the working tree is left
 * clean — a mutated compiler source is never committed.
 *
 * The gates resolve `runar-compiler` / `runar-testing` through the root
 * vitest SRC alias, so a mutated src file is observed WITHOUT a rebuild.
 *
 * A mutant whose patch no longer APPLIES (find string absent, or no longer
 * unique) is reported as STALE and fails the run. It is never counted as a
 * survivor: "the code this mutant patches has changed" and "the safety net has
 * a hole" need opposite fixes, and conflating them is how the two PALMER-1
 * mutants rotted unnoticed after `4b0f688f` restructured branch merging.
 * `__tests__/mutant-staleness.test.ts` re-checks applicability at PR speed,
 * without running a single gate.
 *
 * Usage:
 *   cd conformance && npx tsx mutation/run-mutation.ts          # scorecard
 *   cd conformance && npx tsx mutation/run-mutation.ts --json   # + machine JSON
 *   cd conformance && npx tsx mutation/run-mutation.ts --write-baseline
 *   cd conformance && npx tsx mutation/run-mutation.ts --filter merge-locals
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
/** Repo root: conformance/mutation → conformance → repo root. */
export const REPO_ROOT = resolve(__dirname, '..', '..');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Mutant {
  id: string;
  file: string; // repo-relative in mutants.json
  find: string;
  replace: string;
  class: string;
  stage: string;
  expectCaughtBy: string[];
  /** For documented survivors: gates run to CONFIRM survival. */
  checkGates?: string[];
  /** For documented survivors: the measured coverage hole recorded. */
  finding?: string;
}

export interface MutantResult {
  id: string;
  class: string;
  stage: string;
  caught: boolean;
  survived: boolean;
  caughtBy: string[];
  expectCaughtBy: string[];
  /** True for a mutant intended to survive (empty expectCaughtBy + a finding). */
  documentedSurvivor: boolean;
  /** True when a mutant that MUST be caught was not caught by any gate. */
  unexpectedSurvivor: boolean;
  /** Expected gates that did not fire even though the mutant was caught. */
  missedExpectedGates: string[];
  /** True when the patch could not be applied — the code it targets moved. */
  stale: boolean;
  /** Why the patch did not apply. Present only when `stale`. */
  staleReason?: string;
}

// ---------------------------------------------------------------------------
// Gate table
// ---------------------------------------------------------------------------

interface GateSpec {
  /** cwd relative to repo root. */
  cwd: string;
  /** argv[0] + args passed to spawnSync. */
  argv: string[];
}

export const GATES: Record<string, GateSpec> = {
  'differential-witness': {
    cwd: 'conformance',
    argv: ['npx', 'vitest', 'run', 'witnesses/differential.test.ts'],
  },
  'fold-equivalence': {
    cwd: 'conformance',
    argv: ['npx', 'vitest', 'run', 'witnesses/fold-equivalence.test.ts'],
  },
  'fold-execution': {
    cwd: 'conformance',
    argv: ['npx', 'vitest', 'run', 'witnesses/fold-execution.test.ts'],
  },
  'peephole-exhaustive': {
    cwd: 'packages/runar-compiler',
    argv: ['npx', 'vitest', 'run', 'src/__tests__/peephole-exhaustive.test.ts'],
  },
  // --- Phase E1 / TG-007 (2026-08): Palmer-class corpus additions ----------
  // branch-merged-locals-vm / state-push-framing-vm / c28-state-strict run
  // from the repo root because they live under packages/runar-testing and
  // packages/runar-sdk, which have no nearer vitest config (same root SRC
  // alias as the gates above).
  'branch-merged-locals-vm': {
    cwd: '.',
    argv: ['npx', 'vitest', 'run', 'packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts'],
  },
  // Layer C of the branch lowering (7b888035): `lowerIf` asserts that the
  // parent stackMap describes the physical stack after OP_ENDIF. Registered as
  // a gate so the branch-merge mutants can MEASURE whether it fires rather than
  // assume it does — for a depth-preserving, name-corrupting defect it does not
  // (2026-08-06 drill), and the corpus says so instead of claiming credit.
  'branch-result-depth-invariant': {
    cwd: '.',
    argv: ['npx', 'vitest', 'run', 'packages/runar-compiler/src/__tests__/branch-result-depth-invariant.test.ts'],
  },
  // Real-crypto witness replay for the branch-merged-locals fixture: accept /
  // reject verdicts through the actual @bsv/sdk Spend, not the interpreter.
  'real-crypto-branch-merged-locals': {
    cwd: 'conformance',
    argv: ['npx', 'vitest', 'run', 'witnesses/real-crypto-execution.test.ts', '-t', 'branch-merged-locals'],
  },
  // N-287: real-crypto witness replay for private-helper-outputs — the
  // regression fixture for side-effect-summary.ts's call-graph walk (a public
  // method's continuation shape must reflect side effects buried in a private
  // helper it calls). Deployed through the actual @bsv/sdk Spend, not the
  // interpreter, so a dropped/corrupted effect changes the compiled
  // continuation shape and the real spend rejects.
  'real-crypto-private-helper-outputs': {
    cwd: 'conformance',
    argv: ['npx', 'vitest', 'run', 'witnesses/real-crypto-execution.test.ts', '-t', 'private-helper-outputs'],
  },
  'state-push-framing-vm': {
    cwd: '.',
    argv: ['npx', 'vitest', 'run', 'packages/runar-testing/src/__tests__/state-push-framing-vm.test.ts'],
  },
  'c28-state-strict': {
    cwd: '.',
    argv: ['npx', 'vitest', 'run', 'packages/runar-sdk/src/__tests__/c28-state-strict.test.ts'],
  },
  // Compiler<->SDK vertical pin (conformance/sdk-vertical, Phase C3/C4). TS
  // tier only (--tiers typescript) to stay consistent with this corpus's
  // TS-only scope and to avoid the native SDK-tool builds (Rust/Zig/Java)
  // the other 6 tiers need. --filter pins each gate to ONE currently-green
  // case; conformance/sdk-vertical is still being built out by a parallel
  // work stream and 2 of its 31 cases (bigint-neg1, multi-slot-mixed-a) are
  // missing goldens as of this writing — do not remove --filter or widen it
  // without first confirming the whole case set is green, or these gates
  // will "catch" every mutant for a reason that has nothing to do with the
  // mutation.
  'sdk-vertical-constructor-slots': {
    cwd: 'conformance',
    argv: ['npx', 'tsx', 'sdk-vertical/runner/vertical-runner.ts', '--tiers', 'typescript', '--filter', 'bigint-0'],
  },
  'sdk-vertical-codeseparator': {
    cwd: 'conformance',
    argv: ['npx', 'tsx', 'sdk-vertical/runner/vertical-runner.ts', '--tiers', 'typescript', '--filter', 'codesep-tag-zero'],
  },
  // --- v1 audit mutation-survivor triage (2026-08-17) ----------------------
  // Byte pins for four `05-stack-lower.ts` paths the 71-fixture golden corpus
  // never reaches: `StackMap.dup`'s name bookkeeping, the branch-private
  // residue drain's depth-1 special case, the empty-else reconcile predicate,
  // and the #149 `sinkBelow` DISTANCE (as opposed to its already-covered
  // `> 0` guard). Each witness in that file was delta-reduced from the
  // generated program that first distinguished the mutant, and kills exactly
  // the mutants named on it — measured 1:1, not assumed.
  'stack-frame-mutation-pins': {
    cwd: '.',
    argv: ['npx', 'vitest', 'run', 'packages/runar-testing/src/__tests__/stack-frame-mutation-pins.test.ts'],
  },
};

// ---------------------------------------------------------------------------
// Patch apply / revert — exact match, unique, throws otherwise
// ---------------------------------------------------------------------------

function countOccurrences(haystack: string, needle: string): number {
  if (needle.length === 0) return 0;
  let count = 0;
  let idx = haystack.indexOf(needle);
  while (idx !== -1) {
    count++;
    idx = haystack.indexOf(needle, idx + needle.length);
  }
  return count;
}

/** Apply a mutant to `targetPath` (defaults to REPO_ROOT/mutant.file). */
export function applyMutant(mutant: Mutant, targetPath?: string): void {
  const file = targetPath ?? join(REPO_ROOT, mutant.file);
  const content = readFileSync(file, 'utf-8');
  const n = countOccurrences(content, mutant.find);
  if (n === 0) {
    throw new Error(`applyMutant[${mutant.id}]: find string not found (0 times) in ${file}`);
  }
  if (n > 1) {
    throw new Error(`applyMutant[${mutant.id}]: find string not unique (${n} times) in ${file}`);
  }
  writeFileSync(file, content.replace(mutant.find, mutant.replace));
}

/** Revert a mutant from `targetPath` by replacing `replace` back with `find`. */
export function revertMutant(mutant: Mutant, targetPath?: string): void {
  const file = targetPath ?? join(REPO_ROOT, mutant.file);
  const content = readFileSync(file, 'utf-8');
  const n = countOccurrences(content, mutant.replace);
  if (n === 0) {
    throw new Error(`revertMutant[${mutant.id}]: replacement string not found (0 times) in ${file}`);
  }
  if (n > 1) {
    throw new Error(`revertMutant[${mutant.id}]: replacement string not unique (${n} times) in ${file}`);
  }
  writeFileSync(file, content.replace(mutant.replace, mutant.find));
}

/**
 * Undo a mutation without destroying anything that was saved into the file
 * while the gates were running.
 *
 * This repo is worked in several checkouts at once and a gate run holds a
 * mutated compiler source for seconds at a time; a blind
 * `writeFileSync(file, snapshot)` at the end of that window silently discards a
 * concurrent save. So the revert un-applies the PATCH (replace → find) against
 * whatever the file holds now, which is a no-op difference in the normal case
 * and preserves the other edit in the racy one. The snapshot is only forced
 * when the mutated text is no longer there to un-apply, and the caller is told
 * which of the three happened.
 */
export function restoreAfterMutation(
  mutant: Mutant,
  file: string,
  snapshot: string,
): 'clean' | 'reverted-over-concurrent-write' | 'snapshot-forced' {
  const current = readFileSync(file, 'utf-8');
  if (current === snapshot.replace(mutant.find, mutant.replace)) {
    writeFileSync(file, snapshot);
    return 'clean';
  }
  if (countOccurrences(current, mutant.replace) === 1) {
    writeFileSync(file, current.replace(mutant.replace, mutant.find));
    return 'reverted-over-concurrent-write';
  }
  writeFileSync(file, snapshot);
  return 'snapshot-forced';
}

// ---------------------------------------------------------------------------
// Gate execution
// ---------------------------------------------------------------------------

/** Run a gate; returns true if the gate FAILED (i.e. it caught the mutation). */
function runGate(name: string): boolean {
  const spec = GATES[name];
  if (!spec) throw new Error(`unknown gate: ${name}`);
  const [cmd, ...args] = spec.argv;
  const res = spawnSync(cmd!, args, {
    cwd: join(REPO_ROOT, spec.cwd),
    encoding: 'utf-8',
    stdio: 'pipe',
    env: process.env,
  });
  // Non-zero exit => a test failed (or the mutated compiler threw): CAUGHT.
  return res.status !== 0;
}

// ---------------------------------------------------------------------------
// Score one mutant — ALWAYS reverts
// ---------------------------------------------------------------------------

export function scoreMutant(mutant: Mutant): MutantResult {
  const file = join(REPO_ROOT, mutant.file);
  const snapshot = readFileSync(file, 'utf-8'); // for guaranteed restore
  const documentedSurvivor = mutant.expectCaughtBy.length === 0;
  const gatesToRun =
    mutant.expectCaughtBy.length > 0 ? mutant.expectCaughtBy : (mutant.checkGates ?? []);

  const base = {
    id: mutant.id,
    class: mutant.class,
    stage: mutant.stage,
    expectCaughtBy: mutant.expectCaughtBy,
    documentedSurvivor,
  };

  // STALENESS FIRST. If the patch cannot be applied, the mutant scores NOTHING:
  // not caught, not survived. Reporting it as a survivor would be a lie in the
  // most expensive direction — an unexpected survivor reads as "the safety net
  // has a hole", when the truth is "this mutant no longer describes the code".
  // No gate is run: there is nothing to detect.
  try {
    applyMutant(mutant, file);
  } catch (e) {
    return {
      ...base,
      caught: false,
      survived: false,
      caughtBy: [],
      unexpectedSurvivor: false,
      missedExpectedGates: [...mutant.expectCaughtBy],
      stale: true,
      staleReason: (e as Error).message,
    };
  }

  const caughtBy: string[] = [];
  try {
    for (const gate of gatesToRun) {
      if (runGate(gate)) caughtBy.push(gate);
    }
  } finally {
    // Guaranteed revert, even on error — and never over a concurrent save.
    const how = restoreAfterMutation(mutant, file, snapshot);
    if (how !== 'clean') {
      // eslint-disable-next-line no-console
      console.error(
        `  ! ${mutant.id}: ${mutant.file} changed while the gates ran (${how}). ` +
          'Another checkout is editing this file; re-run when it is idle.',
      );
    }
  }

  const caught = caughtBy.length > 0;
  const survived = !caught;
  const missedExpectedGates = mutant.expectCaughtBy.filter((g) => !caughtBy.includes(g));

  return {
    ...base,
    caught,
    survived,
    caughtBy,
    unexpectedSurvivor: mutant.expectCaughtBy.length > 0 && survived,
    missedExpectedGates,
    stale: false,
  };
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

export function loadMutants(path = join(__dirname, 'mutants.json')): Mutant[] {
  const raw = JSON.parse(readFileSync(path, 'utf-8')) as { mutants: Mutant[] };
  return raw.mutants;
}

// ---------------------------------------------------------------------------
// Baseline regression check (nightly CI gate)
// ---------------------------------------------------------------------------

/** The shape read from `baseline.json`'s `results` array (see `serializeBaseline`). */
export type BaselineEntry = Pick<MutantResult, 'id' | 'caught' | 'survived' | 'expectCaughtBy'>;

/**
 * Compare a stamped `baseline.json` against a fresh scorecard run and report
 * every mutant that weakened since the baseline was last written.
 *
 * F-251: this used to be a `for (const b of base)` loop inlined directly in
 * `.github/workflows/fuzzer-nightly.yml`, which only ever looks up a `base`
 * entry's id in `cur` — it never visits a `cur` entry that has no `base`
 * entry at all. `mutants.json` can grow (six `stacklower-*` mutants landed in
 * `ef753a8f6` without a `--write-baseline` re-stamp, by that commit's own
 * deliberate choice: "new ids are simply not compared and cannot produce a
 * false failure") and every one of those un-stamped mutants is then
 * structurally invisible to this specific gate — if one is caught today and
 * survives tomorrow, the forward-only loop has nothing to compare it
 * against and reports nothing. The reverse loop below closes that: a `cur`
 * mutant absent from `base` that must be caught (`expectCaughtBy` non-empty)
 * and is currently surviving is still reported. (The separate "must never
 * survive" scorecard gate in `score()`/`main()` already catches a *brand
 * new* mutant that is born surviving; this function is the regression-since-
 * last-stamp gate, and the point is that un-stamped is not the same as
 * exempt from it.)
 */
export function findBaselineRegressions(base: BaselineEntry[], cur: MutantResult[]): string[] {
  const curById = new Map(cur.map((r) => [r.id, r]));
  const baseIds = new Set(base.map((b) => b.id));
  const regressions: string[] = [];
  for (const b of base) {
    const c = curById.get(b.id);
    if (!c) {
      regressions.push(`${b.id} (missing from current run)`);
      continue;
    }
    if (b.caught && c.survived) regressions.push(`${b.id} (was caught, now SURVIVES)`);
  }
  for (const c of cur) {
    if (!baseIds.has(c.id) && c.expectCaughtBy.length > 0 && c.survived) {
      regressions.push(`${c.id} (no baseline entry, and currently SURVIVES)`);
    }
  }
  return regressions;
}

// ---------------------------------------------------------------------------
// Scorecard driver
// ---------------------------------------------------------------------------

export interface Scorecard {
  total: number;
  expected: number; // mutants with a non-empty expectCaughtBy
  caughtExpected: number;
  unexpectedSurvivors: MutantResult[];
  documentedSurvivors: MutantResult[];
  /** Mutants whose patch no longer applies — scored as neither caught nor survived. */
  stale: MutantResult[];
  /**
   * Mutants that were `caught` (so not an `unexpectedSurvivor`) but where at
   * least one gate the mutant itself nominated in `expectCaughtBy` never
   * fired. `scoreMutant` only runs the gates a mutant nominates, so "caught"
   * means "one of the gates this mutant already believed would catch it
   * did" — a sibling gate can go silently dead forever and `caught: true`
   * would hide it. This bucket is what makes that visible to the exit code
   * (F-172).
   */
  partiallyCaught: MutantResult[];
  results: MutantResult[];
}

export function score(mutants: Mutant[]): Scorecard {
  const results = mutants.map(scoreMutant);
  // Stale mutants are excluded from the denominator too: a corpus that cannot
  // be applied has not measured anything, and counting it as "expected to be
  // caught" would quietly deflate the score instead of naming the problem.
  const expectedResults = results.filter((r) => r.expectCaughtBy.length > 0 && !r.stale);
  return {
    total: results.length,
    expected: expectedResults.length,
    caughtExpected: expectedResults.filter((r) => r.caught).length,
    unexpectedSurvivors: results.filter((r) => r.unexpectedSurvivor),
    documentedSurvivors: results.filter((r) => r.documentedSurvivor && !r.stale),
    stale: results.filter((r) => r.stale),
    partiallyCaught: results.filter(
      (r) => !r.documentedSurvivor && r.caught && r.missedExpectedGates.length > 0,
    ),
    results,
  };
}

function printScorecard(card: Scorecard, mutants: Mutant[]): void {
  const findingById = new Map(mutants.map((m) => [m.id, m.finding]));
  /* eslint-disable no-console */
  console.log('');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('  Rúnar mutation scorecard (TS-GAP-006)');
  console.log('════════════════════════════════════════════════════════════════');
  console.log(`  caught ${card.caughtExpected}/${card.expected} mutants that MUST be caught`);
  console.log(`  (${card.total} total mutants; ${card.documentedSurvivors.length} documented survivor(s))`);
  console.log('');
  for (const r of card.results) {
    const tag = r.stale
      ? 'STALE'
      : r.documentedSurvivor
      ? r.caught
        ? 'SURVIVOR→CAUGHT'
        : 'survivor (doc)'
      : r.caught
        ? 'caught'
        : 'SURVIVED';
    const gates = r.caughtBy.length ? ` by [${r.caughtBy.join(', ')}]` : '';
    console.log(`  ${tag.padEnd(16)} ${r.id.padEnd(34)} ${r.class} / ${r.stage}${gates}`);
    if (!r.documentedSurvivor && r.missedExpectedGates.length && r.caught) {
      console.log(`      ⚠ expected gate(s) did NOT fire: ${r.missedExpectedGates.join(', ')}`);
    }
  }
  console.log('');
  if (card.documentedSurvivors.length) {
    console.log('  Documented survivors (measured holes — NOT hidden):');
    for (const r of card.documentedSurvivors) {
      const finding = findingById.get(r.id);
      console.log(`   • ${r.id} (${r.class} / ${r.stage})${r.caught ? ' — NOW CAUGHT, update corpus' : ''}`);
      if (finding) console.log(`     ${finding}`);
    }
    console.log('');
  }
  if (card.stale.length) {
    console.log('  ✗ STALE MUTANTS — the code they patch has changed; they measured NOTHING:');
    for (const r of card.stale) {
      console.log(`   • ${r.id} (${r.class} / ${r.stage})`);
      console.log(`     ${r.staleReason ?? 'patch did not apply'}`);
    }
    console.log('     Re-derive each against the current source and re-measure which gates');
    console.log('     fire. A stale mutant is NOT a survivor and NOT a coverage hole.');
    console.log('');
  }
  if (card.unexpectedSurvivors.length) {
    console.log('  ✗ UNEXPECTED SURVIVORS (real holes in the net — MUST be addressed):');
    for (const r of card.unexpectedSurvivors) {
      console.log(`   • ${r.id} (${r.class} / ${r.stage}) — expected ${r.expectCaughtBy.join(', ')}`);
    }
    console.log('');
  }
  if (card.partiallyCaught.length) {
    console.log('  ✗ PARTIALLY CAUGHT (a nominated gate never fired — MUST be addressed):');
    for (const r of card.partiallyCaught) {
      console.log(
        `   • ${r.id} (${r.class} / ${r.stage}) — caught by [${r.caughtBy.join(', ')}], ` +
          `dead gate(s): ${r.missedExpectedGates.join(', ')}`,
      );
    }
    console.log('');
  }
  /* eslint-enable no-console */
}

function serializeBaseline(card: Scorecard): string {
  const baseline = {
    _doc: 'Per-mutant caught/survived reference for the TS-GAP-006 nightly regression gate.',
    generatedFrom: 'conformance/mutation/mutants.json',
    results: card.results.map((r) => ({
      id: r.id,
      class: r.class,
      stage: r.stage,
      caught: r.caught,
      survived: r.survived,
      caughtBy: r.caughtBy,
      expectCaughtBy: r.expectCaughtBy,
      documentedSurvivor: r.documentedSurvivor,
      stale: r.stale,
    })),
  };
  return JSON.stringify(baseline, null, 2) + '\n';
}

function main(): void {
  const args = process.argv.slice(2);
  // `--filter <substr>` scores only the matching mutant ids. Written for the
  // re-derivation loop: each run applies a patch to a REAL compiler source file
  // in the working tree, so scoring one mutant instead of 22 keeps that window
  // as short as possible when the checkout is shared. A filtered run never
  // writes the baseline (it would drop every mutant it skipped).
  const filterIdx = args.indexOf('--filter');
  const filter = filterIdx !== -1 ? args[filterIdx + 1] : undefined;
  const allMutants = loadMutants();
  const mutants = filter ? allMutants.filter((m) => m.id.includes(filter)) : allMutants;
  if (filter && mutants.length === 0) {
    // eslint-disable-next-line no-console
    console.error(`--filter '${filter}' matched no mutant id`);
    process.exitCode = 2;
    return;
  }
  if (filter && args.includes('--write-baseline')) {
    // eslint-disable-next-line no-console
    console.error('--filter and --write-baseline are mutually exclusive (a partial baseline is a lie)');
    process.exitCode = 2;
    return;
  }
  const card = score(mutants);
  printScorecard(card, mutants);

  // Accept both `--json-out=PATH` and `--json-out PATH`.
  let jsonOutPath: string | undefined;
  const eqArg = args.find((a) => a.startsWith('--json-out='));
  if (eqArg) {
    jsonOutPath = eqArg.slice('--json-out='.length);
  } else {
    const flagIdx = args.indexOf('--json-out');
    if (flagIdx !== -1 && args[flagIdx + 1]) jsonOutPath = args[flagIdx + 1];
  }

  if (args.includes('--write-baseline')) {
    const out = join(__dirname, 'baseline.json');
    writeFileSync(out, serializeBaseline(card));
    // eslint-disable-next-line no-console
    console.log(`  baseline written → ${out}`);
  } else if (jsonOutPath) {
    writeFileSync(resolve(jsonOutPath), serializeBaseline(card));
  } else if (args.includes('--json')) {
    // eslint-disable-next-line no-console
    console.log(serializeBaseline(card));
  }

  // Fail the run if any mutant that MUST be caught survived (net weakened), if
  // any mutant is stale (the corpus no longer describes the code it grades),
  // or if a caught mutant's nominated gate list contains one that never fired
  // (F-172: `caught: true` must not hide a dead sibling gate — "caught" would
  // otherwise mean only "one of the gates this mutant already believed would
  // catch it did").
  if (card.unexpectedSurvivors.length > 0 || card.stale.length > 0 || card.partiallyCaught.length > 0) {
    process.exitCode = 1;
  }
}

// Run main() only when executed directly (not when imported by the unit test).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
