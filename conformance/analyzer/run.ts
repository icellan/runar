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
 * Currently only the TypeScript tier is wired in. The other six tiers
 * (Go, Rust, Python, Zig, Ruby, Java) attach themselves by dropping a
 * wrapper script under `tools/analyzer-runner/`.
 *
 * Usage:
 *   ./node_modules/.pnpm/node_modules/.bin/tsx conformance/analyzer/run.ts
 *
 *   # Or filter:
 *   ./node_modules/.pnpm/node_modules/.bin/tsx conformance/analyzer/run.ts \
 *     --tiers ts,go --fixtures basic-p2pkh,escrow
 *
 * Exits 0 on success, non-zero on any tier × fixture mismatch.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
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

  if (fails.length > 0 || errors.length > 0) process.exit(1);
}

main();
