// Script-size regression benchmark for Rúnar conformance fixtures.
//
// For every fixture under conformance/tests/<name>/expected-script.hex, the
// compiled Bitcoin Script byte length is compared against the entry in
// conformance/script-size-baseline.json. The check fails CI when any fixture
// grows beyond a 10 % tolerance or shrinks by more than 50 % (the latter is
// almost always a missing / blanked-out fixture rather than a real
// optimisation).
//
// Run modes:
//   pnpm script-size-check            # verify (CI mode)
//   pnpm script-size-check -- --update  # re-stamp baseline (maintainer only)
//
// Maintainers re-stamp the baseline only on intentional size-change PRs and
// must justify the new numbers in the PR description (e.g. "new peephole
// pass shaves 4 % off math-demo"). See .github/workflows/script-size-benchmark.yml
// for the CI wiring.

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Resolve to .../conformance/ regardless of cwd. */
export const CONFORMANCE_ROOT = resolve(__dirname, '..');
export const TESTS_DIR = join(CONFORMANCE_ROOT, 'tests');
export const BASELINE_PATH = join(CONFORMANCE_ROOT, 'script-size-baseline.json');

/** Growth above this percent fails CI. */
export const GROWTH_TOLERANCE_PCT = 10;
/** Shrinkage beyond this percent fails CI (suspicious — likely a missing fixture). */
export const SHRINK_TOLERANCE_PCT = 50;

export type Baseline = {
  _comment?: string;
  _tolerance_growth_percent?: number;
  _tolerance_shrink_percent?: number;
  fixtures: Record<string, number>;
};

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'missing-current' | 'missing-baseline';

export interface FixtureResult {
  fixture: string;
  baseline: number | null;
  current: number | null;
  /** delta as a fraction (0.10 = +10 %). null when either side is missing. */
  delta: number | null;
  status: CheckStatus;
  message: string;
}

export interface CheckReport {
  results: FixtureResult[];
  ok: number;
  warn: number;
  fail: number;
  missing: number;
  failed: boolean;
}

/** Byte length of a `expected-script.hex` file (strips trailing whitespace,
 *  ignores any internal whitespace, halves character count). Throws on odd
 *  hex length or non-hex characters so a corrupt fixture surfaces loudly. */
export function hexFileByteLength(path: string): number {
  const raw = readFileSync(path, 'utf8');
  const stripped = raw.replace(/\s+/g, '');
  if (stripped.length % 2 !== 0) {
    throw new Error(`Odd hex length in ${path}: ${stripped.length} chars`);
  }
  if (stripped.length > 0 && !/^[0-9a-fA-F]+$/.test(stripped)) {
    throw new Error(`Non-hex characters in ${path}`);
  }
  return stripped.length / 2;
}

/** Enumerate fixtures by scanning conformance/tests/<name>/expected-script.hex. */
export function discoverFixtures(testsDir: string = TESTS_DIR): Map<string, string> {
  const out = new Map<string, string>();
  if (!existsSync(testsDir)) return out;
  for (const entry of readdirSync(testsDir).sort()) {
    const dir = join(testsDir, entry);
    if (!statSync(dir).isDirectory()) continue;
    const hex = join(dir, 'expected-script.hex');
    if (existsSync(hex)) out.set(entry, hex);
  }
  return out;
}

export function loadBaseline(path: string = BASELINE_PATH): Baseline {
  const raw = readFileSync(path, 'utf8');
  const parsed = JSON.parse(raw) as Baseline;
  if (!parsed || typeof parsed !== 'object' || !parsed.fixtures) {
    throw new Error(`Invalid baseline file ${path}: missing "fixtures" object`);
  }
  return parsed;
}

/** Pure: classify a single fixture's current vs baseline bytes. */
export function classify(
  fixture: string,
  baseline: number | null,
  current: number | null,
  growthPct: number = GROWTH_TOLERANCE_PCT,
  shrinkPct: number = SHRINK_TOLERANCE_PCT,
): FixtureResult {
  if (baseline === null) {
    return {
      fixture,
      baseline,
      current,
      delta: null,
      status: 'missing-baseline',
      message: `${fixture}: no baseline entry. Re-stamp the baseline with --update if this fixture is intentionally new.`,
    };
  }
  if (current === null) {
    return {
      fixture,
      baseline,
      current,
      delta: null,
      status: 'missing-current',
      message: `${fixture}: baseline=${baseline} bytes but expected-script.hex is missing. Was the fixture deleted? If intentional, re-stamp the baseline.`,
    };
  }
  if (baseline === 0) {
    // Avoid div-by-zero; treat any nonzero current as +∞ growth, identical as ok.
    if (current === 0) {
      return { fixture, baseline, current, delta: 0, status: 'ok', message: `${fixture}: 0 bytes (unchanged)` };
    }
    return {
      fixture,
      baseline,
      current,
      delta: Number.POSITIVE_INFINITY,
      status: 'fail',
      message: `${fixture}: baseline=0 bytes, current=${current} bytes (infinite growth from zero baseline)`,
    };
  }
  const delta = (current - baseline) / baseline;
  const deltaPctStr = `${(delta * 100).toFixed(2)}%`;
  if (delta > growthPct / 100) {
    return {
      fixture,
      baseline,
      current,
      delta,
      status: 'fail',
      message: `${fixture}: baseline=${baseline} bytes, current=${current} bytes, delta=${delta >= 0 ? '+' : ''}${deltaPctStr} (threshold +${growthPct}%)`,
    };
  }
  if (delta < -(shrinkPct / 100)) {
    return {
      fixture,
      baseline,
      current,
      delta,
      status: 'fail',
      message: `${fixture}: baseline=${baseline} bytes, current=${current} bytes, delta=${deltaPctStr} (suspicious shrinkage past -${shrinkPct}%)`,
    };
  }
  if (delta > 0) {
    return {
      fixture,
      baseline,
      current,
      delta,
      status: 'warn',
      message: `${fixture}: baseline=${baseline} bytes, current=${current} bytes, delta=+${deltaPctStr} (within +${growthPct}% tolerance)`,
    };
  }
  if (delta < 0) {
    return {
      fixture,
      baseline,
      current,
      delta,
      status: 'ok',
      message: `${fixture}: baseline=${baseline} bytes, current=${current} bytes, delta=${deltaPctStr} (shrunk)`,
    };
  }
  return {
    fixture,
    baseline,
    current,
    delta,
    status: 'ok',
    message: `${fixture}: ${baseline} bytes (unchanged)`,
  };
}

/** Compare every fixture under testsDir against baseline, returning a report. */
export function runComparison(
  baseline: Baseline,
  testsDir: string = TESTS_DIR,
): CheckReport {
  const growthPct = baseline._tolerance_growth_percent ?? GROWTH_TOLERANCE_PCT;
  const shrinkPct = baseline._tolerance_shrink_percent ?? SHRINK_TOLERANCE_PCT;
  const current = discoverFixtures(testsDir);
  const allNames = new Set<string>([
    ...Object.keys(baseline.fixtures),
    ...current.keys(),
  ]);

  const results: FixtureResult[] = [];
  for (const name of [...allNames].sort()) {
    const baseBytes = Object.prototype.hasOwnProperty.call(baseline.fixtures, name)
      ? baseline.fixtures[name]
      : null;
    const hexPath = current.get(name);
    const curBytes = hexPath ? hexFileByteLength(hexPath) : null;
    results.push(classify(name, baseBytes, curBytes, growthPct, shrinkPct));
  }

  let ok = 0;
  let warn = 0;
  let fail = 0;
  let missing = 0;
  for (const r of results) {
    if (r.status === 'ok') ok++;
    else if (r.status === 'warn') warn++;
    else if (r.status === 'fail') fail++;
    else missing++;
  }

  // Missing-baseline / missing-current both fail the run — silent additions
  // and silent deletions are exactly the regressions this benchmark catches.
  const failed = fail > 0 || missing > 0;
  return { results, ok, warn, fail, missing, failed };
}

/** Restamp the baseline file from current fixture sizes. Preserves the
 *  comment + tolerance metadata; rewrites only the fixtures map. */
export function rewriteBaseline(
  testsDir: string = TESTS_DIR,
  baselinePath: string = BASELINE_PATH,
): { written: number; path: string } {
  let existing: Baseline | undefined;
  try {
    existing = loadBaseline(baselinePath);
  } catch {
    existing = undefined;
  }
  const fixtures: Record<string, number> = {};
  const discovered = discoverFixtures(testsDir);
  for (const name of [...discovered.keys()].sort()) {
    fixtures[name] = hexFileByteLength(discovered.get(name)!);
  }
  const next: Baseline = {
    _comment:
      existing?._comment ??
      'Script-size regression baseline. Byte length of expected-script.hex per fixture. Regenerate with: pnpm script-size-check -- --update (only on intentional size-change PRs, justify in PR description). See conformance/runner/script-size-check.ts.',
    _tolerance_growth_percent:
      existing?._tolerance_growth_percent ?? GROWTH_TOLERANCE_PCT,
    _tolerance_shrink_percent:
      existing?._tolerance_shrink_percent ?? SHRINK_TOLERANCE_PCT,
    fixtures,
  };
  writeFileSync(baselinePath, JSON.stringify(next, null, 2) + '\n', 'utf8');
  return { written: Object.keys(fixtures).length, path: baselinePath };
}

/** Format a report as a multi-line human-readable string. */
export function formatReport(report: CheckReport): string {
  const lines: string[] = [];
  lines.push('Script-size regression check');
  lines.push('-----------------------------');
  const fails = report.results.filter((r) => r.status === 'fail');
  const missing = report.results.filter(
    (r) => r.status === 'missing-baseline' || r.status === 'missing-current',
  );
  const warns = report.results.filter((r) => r.status === 'warn');

  if (fails.length > 0) {
    lines.push('');
    lines.push(`FAIL (${fails.length}):`);
    for (const r of fails) lines.push(`  - ${r.message}`);
  }
  if (missing.length > 0) {
    lines.push('');
    lines.push(`MISSING (${missing.length}):`);
    for (const r of missing) lines.push(`  - ${r.message}`);
  }
  if (warns.length > 0) {
    lines.push('');
    lines.push(`WARN (${warns.length}):`);
    for (const r of warns) lines.push(`  - ${r.message}`);
  }
  lines.push('');
  lines.push(
    `Summary: ok=${report.ok} warn=${report.warn} fail=${report.fail} missing=${report.missing} (total=${report.results.length})`,
  );
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function cli(argv: string[]): number {
  const update = argv.includes('--update');
  if (update) {
    const { written, path } = rewriteBaseline();
    // eslint-disable-next-line no-console
    console.log(`Re-stamped baseline at ${path} (${written} fixtures)`);
    return 0;
  }
  const baseline = loadBaseline();
  const report = runComparison(baseline);
  // eslint-disable-next-line no-console
  console.log(formatReport(report));
  return report.failed ? 1 : 0;
}

// Run only when invoked directly (not when imported by tests).
const invokedDirectly =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  process.exit(cli(process.argv.slice(2)));
}
