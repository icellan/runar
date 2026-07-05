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
 * Usage:
 *   cd conformance && npx tsx mutation/run-mutation.ts          # scorecard
 *   cd conformance && npx tsx mutation/run-mutation.ts --json   # + machine JSON
 *   cd conformance && npx tsx mutation/run-mutation.ts --write-baseline
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

  const caughtBy: string[] = [];
  try {
    applyMutant(mutant, file);
    for (const gate of gatesToRun) {
      if (runGate(gate)) caughtBy.push(gate);
    }
  } finally {
    // Guaranteed revert: restore the exact pre-mutation bytes, even on error.
    writeFileSync(file, snapshot);
  }

  const caught = caughtBy.length > 0;
  const survived = !caught;
  const missedExpectedGates = mutant.expectCaughtBy.filter((g) => !caughtBy.includes(g));

  return {
    id: mutant.id,
    class: mutant.class,
    stage: mutant.stage,
    caught,
    survived,
    caughtBy,
    expectCaughtBy: mutant.expectCaughtBy,
    documentedSurvivor,
    unexpectedSurvivor: mutant.expectCaughtBy.length > 0 && survived,
    missedExpectedGates,
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
// Scorecard driver
// ---------------------------------------------------------------------------

export interface Scorecard {
  total: number;
  expected: number; // mutants with a non-empty expectCaughtBy
  caughtExpected: number;
  unexpectedSurvivors: MutantResult[];
  documentedSurvivors: MutantResult[];
  results: MutantResult[];
}

export function score(mutants: Mutant[]): Scorecard {
  const results = mutants.map(scoreMutant);
  const expectedResults = results.filter((r) => r.expectCaughtBy.length > 0);
  return {
    total: results.length,
    expected: expectedResults.length,
    caughtExpected: expectedResults.filter((r) => r.caught).length,
    unexpectedSurvivors: results.filter((r) => r.unexpectedSurvivor),
    documentedSurvivors: results.filter((r) => r.documentedSurvivor),
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
    const tag = r.documentedSurvivor
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
  if (card.unexpectedSurvivors.length) {
    console.log('  ✗ UNEXPECTED SURVIVORS (real holes in the net — MUST be addressed):');
    for (const r of card.unexpectedSurvivors) {
      console.log(`   • ${r.id} (${r.class} / ${r.stage}) — expected ${r.expectCaughtBy.join(', ')}`);
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
    })),
  };
  return JSON.stringify(baseline, null, 2) + '\n';
}

function main(): void {
  const args = process.argv.slice(2);
  const mutants = loadMutants();
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

  // Fail the run if any mutant that MUST be caught survived (net weakened).
  if (card.unexpectedSurvivors.length > 0) {
    process.exitCode = 1;
  }
}

// Run main() only when executed directly (not when imported by the unit test).
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
