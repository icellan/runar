/**
 * Conformance driver for the Bitcoin Script static analyzer.
 *
 * For each fixture × tier, invokes the tier's analyzer CLI on the hex
 * input at `conformance/tests/<fixture>/expected-script.hex` and diffs
 * the produced JSON report against the golden at
 * `conformance/analyzer/<fixture>/expected-analyzer-report.json`.
 *
 * Tiers are discovered by their wrapper script existing under
 * `tools/analyzer-runner/<tier>.sh`. The wrapper takes a single argument
 * (the hex file path) and writes the JSON report to stdout.
 *
 * R-219: this used to say only the TypeScript tier was wired in. All seven
 * ship a wrapper and all seven pass — 8 fixtures x 7 tiers, 56/56. A tier
 * attaches itself by dropping a wrapper script under `tools/analyzer-runner/`,
 * so the set is discovered rather than listed here.
 *
 * Because the set is DISCOVERED, a deleted or renamed wrapper used to mean
 * its 8 fixtures reported `skip` and the driver still exited 0 — the 56/56
 * above was prose, and nothing asserted it. A missing wrapper is now a missing
 * tier: hard-fail under `CI=true` or `RUNAR_CONFORMANCE_STRICT`, and a loud
 * INCOMPLETE COVERAGE warning locally so a run without every toolchain is
 * still usable. The pass count is checked against the selected matrix. This
 * mirrors `assertAllCompilersAvailableInCi` in conformance/runner/runner.ts
 * rather than inventing a second convention.
 *
 * Usage:
 *   ./node_modules/.pnpm/node_modules/.bin/tsx conformance/analyzer/run.ts
 *
 *   # Or filter:
 *   ./node_modules/.pnpm/node_modules/.bin/tsx conformance/analyzer/run.ts \
 *     --tiers ts,go --fixtures basic-p2pkh,escrow
 *
 * Exits 0 on success, non-zero on any tier × fixture mismatch, and non-zero
 * under CI when a selected tier has no wrapper at all.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..');

const ALL_FIXTURES = [
  'basic-p2pkh',
  'escrow',
  'stateful-counter',
  'auction',
  'covenant-vault',
  'ec-demo',
  'schnorr-zkp',
  'if-else',
];

const ALL_TIERS = ['ts', 'go', 'rust', 'python', 'zig', 'ruby', 'java'];

interface CliArgs {
  tiers: string[];
  fixtures: string[];
}

function parseArgs(argv: string[]): CliArgs {
  let tiers = ALL_TIERS;
  let fixtures = ALL_FIXTURES;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--tiers' && i + 1 < argv.length) {
      tiers = argv[++i]!.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (a === '--fixtures' && i + 1 < argv.length) {
      fixtures = argv[++i]!.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: run.ts [--tiers ts,go,...] [--fixtures basic-p2pkh,...]',
      );
      process.exit(0);
    }
  }
  return { tiers, fixtures };
}

export type MissingTierAction = 'ok' | 'warn' | 'fail';

/**
 * What to do when a selected tier has no `tools/analyzer-runner/<tier>.sh`.
 *
 * A wrapper that is simply absent produced `status: 'skip'`, and the exit
 * condition only looked at fails and errors — so deleting a wrapper removed
 * 8 fixtures from the matrix and CI stayed green. Locally that tolerance is
 * wanted (not every dev has every toolchain); in CI it is the whole gate.
 *
 * Deliberately identical in shape and env-var vocabulary to
 * `decideMissingCompilerAction` in conformance/runner/runner.ts.
 */
export function decideMissingTierAction(
  missing: string[],
  env: { CI?: string; RUNAR_CONFORMANCE_STRICT?: string },
): MissingTierAction {
  if (missing.length === 0) return 'ok';
  if (env.CI === 'true') return 'fail';
  const strict = env.RUNAR_CONFORMANCE_STRICT;
  if (strict === '1' || strict === 'true') return 'fail';
  return 'warn';
}

/**
 * Check the pass count against the matrix that was actually selected.
 *
 * The file header claims "8 fixtures x 7 tiers, 56/56" and nothing checked
 * it. A run that passed 48 of 56 — or 0 of 56, which is what a fully
 * detached matrix produces — reported success. Returns the operator-facing
 * message, or null when every selected pair passed.
 */
export function coverageShortfallError(
  passes: number,
  ctx: { tiers: number; fixtures: number },
): string | null {
  const expected = ctx.tiers * ctx.fixtures;
  if (passes === expected) return null;
  return (
    `[conformance/analyzer] COVERAGE SHORTFALL: ${passes} of ${expected} ` +
    `(fixture x tier) pairs passed — ${ctx.fixtures} fixture(s) x ${ctx.tiers} tier(s).\n` +
    `  A pair that was skipped was never compared against its golden.\n` +
    `  A run that did not evaluate the whole matrix must not be reported as a pass.`
  );
}

function runTier(tier: string, hexPath: string): string {
  const wrapper = join(REPO_ROOT, 'tools', 'analyzer-runner', `${tier}.sh`);
  if (!existsSync(wrapper)) {
    throw new Error(
      `[${tier}] no wrapper script found at ${wrapper}; tier not yet attached`,
    );
  }
  return execFileSync(wrapper, [hexPath], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024, // 256 MB — ec-demo golden alone is ~18 MB
  });
}

interface Result {
  tier: string;
  fixture: string;
  status: 'pass' | 'fail' | 'skip' | 'error';
  detail?: string;
}

function diffReports(actual: string, expected: string): string | null {
  if (actual === expected) return null;
  const aLines = actual.split('\n');
  const eLines = expected.split('\n');
  const n = Math.max(aLines.length, eLines.length);
  for (let i = 0; i < n; i++) {
    if (aLines[i] !== eLines[i]) {
      const ctx = (lines: string[], idx: number): string => {
        const lo = Math.max(0, idx - 2);
        const hi = Math.min(lines.length, idx + 3);
        return lines
          .slice(lo, hi)
          .map((l, j) => `  ${lo + j + 1}: ${l}`)
          .join('\n');
      };
      return (
        `first divergence at line ${i + 1}\n` +
        `--- expected ---\n${ctx(eLines, i)}\n` +
        `--- actual ---\n${ctx(aLines, i)}`
      );
    }
  }
  return 'reports differ but no line diverged (length mismatch?)';
}

function main(): void {
  const { tiers, fixtures } = parseArgs(process.argv.slice(2));

  // Probe the wrapper set BEFORE doing any work. A tier attaches by dropping
  // `tools/analyzer-runner/<tier>.sh`; a tier whose wrapper is gone is a tier
  // that will report `skip` for every fixture, and skips used to exit 0.
  const missingTiers = tiers.filter(
    (tier) => !existsSync(join(REPO_ROOT, 'tools', 'analyzer-runner', `${tier}.sh`)),
  );
  const missingAction = decideMissingTierAction(missingTiers, process.env);
  if (missingAction === 'fail') {
    const reason =
      process.env.CI === 'true' ? 'CI=true' : 'RUNAR_CONFORMANCE_STRICT set';
    console.error('');
    console.error(
      `[conformance/analyzer] ${reason} but ${missingTiers.length} tier` +
        (missingTiers.length === 1 ? '' : 's') +
        ` ha${missingTiers.length === 1 ? 's' : 've'} no analyzer wrapper: ` +
        `${missingTiers.join(', ')}.\n` +
        `  Searched: tools/analyzer-runner/<tier>.sh\n` +
        `  Every selected tier must be attached, or the run silently covers ` +
        `less than it claims.`,
    );
    console.error('');
    process.exit(1);
  }
  if (missingAction === 'warn') {
    console.error('');
    console.error(
      `[conformance/analyzer] INCOMPLETE COVERAGE: ${missingTiers.length} tier` +
        (missingTiers.length === 1 ? ' has' : 's have') +
        ` no analyzer wrapper and will NOT be exercised: ${missingTiers.join(', ')}.\n` +
        `  A PASS from this run does NOT mean all seven tiers agree.\n` +
        `  Set RUNAR_CONFORMANCE_STRICT=1 to make a detached tier a non-zero exit locally.`,
    );
    console.error('');
  }

  const results: Result[] = [];

  for (const fixture of fixtures) {
    const hexPath = join(
      REPO_ROOT,
      'conformance',
      'tests',
      fixture,
      'expected-script.hex',
    );
    const goldenPath = join(
      REPO_ROOT,
      'conformance',
      'analyzer',
      fixture,
      'expected-analyzer-report.json',
    );

    if (!existsSync(hexPath)) {
      for (const tier of tiers) {
        results.push({
          tier,
          fixture,
          status: 'error',
          detail: `no hex at ${hexPath}`,
        });
      }
      continue;
    }
    if (!existsSync(goldenPath)) {
      for (const tier of tiers) {
        results.push({
          tier,
          fixture,
          status: 'error',
          detail: `no golden at ${goldenPath}`,
        });
      }
      continue;
    }

    const golden = readFileSync(goldenPath, 'utf8');

    for (const tier of tiers) {
      try {
        const actual = runTier(tier, hexPath);
        const diff = diffReports(actual, golden);
        if (diff === null) {
          results.push({ tier, fixture, status: 'pass' });
        } else {
          results.push({ tier, fixture, status: 'fail', detail: diff });
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('tier not yet attached')) {
          results.push({ tier, fixture, status: 'skip', detail: msg });
        } else {
          results.push({ tier, fixture, status: 'error', detail: msg });
        }
      }
    }
  }

  // Render summary
  const passes = results.filter((r) => r.status === 'pass');
  const fails = results.filter((r) => r.status === 'fail');
  const skips = results.filter((r) => r.status === 'skip');
  const errors = results.filter((r) => r.status === 'error');

  console.log(`\n=== analyzer conformance ===`);
  console.log(
    `pass: ${passes.length}  fail: ${fails.length}  skip: ${skips.length}  error: ${errors.length}\n`,
  );

  for (const r of fails) {
    console.log(`FAIL ${r.tier} × ${r.fixture}`);
    if (r.detail) console.log(r.detail.replace(/^/gm, '  '));
  }
  for (const r of errors) {
    console.log(`ERROR ${r.tier} × ${r.fixture}: ${r.detail ?? ''}`);
  }
  if (skips.length > 0) {
    const by = new Map<string, number>();
    for (const r of skips) by.set(r.tier, (by.get(r.tier) ?? 0) + 1);
    for (const [tier, n] of by) {
      console.log(`SKIP ${tier}: not yet attached (${n} fixture(s))`);
    }
  }

  // Assert the matrix. Until now the "56/56" in the header was prose: a
  // detached tier turned 8 pairs into `skip` and the run still exited 0.
  const shortfall = coverageShortfallError(passes.length, {
    tiers: tiers.length,
    fixtures: fixtures.length,
  });
  if (shortfall !== null) {
    console.error('');
    console.error(shortfall);
    console.error('');
  }

  // A local run with a tier detached stays usable: it already printed
  // INCOMPLETE COVERAGE and the shortfall above, and exits 0 so a dev without
  // every toolchain can still use the driver. Under CI / strict the missing
  // wrapper already exited 1 before any work was done.
  if (fails.length > 0 || errors.length > 0) process.exit(1);
  if (shortfall !== null && missingAction === 'ok') process.exit(1);
}

// Importable for tests: only run the driver when this file IS the entry point.
const thisFile = realpathSync(fileURLToPath(import.meta.url));
const entry = process.argv[1] ? realpathSync(process.argv[1]) : '';
if (entry === thisFile) main();
