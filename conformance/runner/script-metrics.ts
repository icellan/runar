/**
 * Script-size instrumentation runner.
 *
 * `script-size-check.ts` answers "did any fixture grow?"; this answers the
 * next question: "where did the bytes go?". For every conformance fixture it
 * buckets the serialized script by byte category and reports the constants
 * that dominate, so an optimization can be aimed at the term that actually
 * costs something rather than at whatever is easiest to change.
 *
 * Two sources of script bytes:
 *
 *   default  — read the checked-in `expected-script.hex`. Fast, needs no
 *              compilation, and is exactly what CI ships.
 *   --compile — recompile each fixture's `.runar.ts` through the TS reference
 *              compiler with a given option set. This is how an experimental
 *              flag is benchmarked against the baseline; pass `--compare` to
 *              run several option sets and print the deltas.
 *
 * Usage:
 *   tsx runner/script-metrics.ts                        # goldens, markdown table
 *   tsx runner/script-metrics.ts --json out.json        # machine-readable
 *   tsx runner/script-metrics.ts --fixture p256-wallet --detail
 *   tsx runner/script-metrics.ts --compile --compare current,liveness
 *
 * Read-only: it never writes a golden or a baseline.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import {
  analyzeScriptHex,
  type ByteCategory,
  type ScriptMetrics,
} from '../../packages/runar-compiler/src/metrics/script-metrics.js';
import { compile, type CompileOptions } from '../../packages/runar-compiler/src/index.js';
import { CONFORMANCE_ROOT, TESTS_DIR, discoverFixtures } from './script-size-check.js';

const REPO_ROOT = resolve(CONFORMANCE_ROOT, '..');

// ---------------------------------------------------------------------------
// Fixture sources
// ---------------------------------------------------------------------------

interface SourceConfig {
  sources?: Record<string, string>;
  compilers?: string[];
}

/** Absolute path to a fixture's `.runar.ts` source, or null if it ships none. */
export function tsSourcePath(fixture: string, testsDir: string = TESTS_DIR): string | null {
  const configFile = join(testsDir, fixture, 'source.json');
  if (!existsSync(configFile)) return null;
  const config = JSON.parse(readFileSync(configFile, 'utf8')) as SourceConfig;
  const rel = config.sources?.['.runar.ts'];
  if (rel === undefined) return null;
  const abs = resolve(testsDir, fixture, rel);
  if (!existsSync(abs)) {
    throw new Error(`source.json for '${fixture}' points at a missing file: ${abs}`);
  }
  return abs;
}

// ---------------------------------------------------------------------------
// Option sets ("variants") a benchmark can compare
// ---------------------------------------------------------------------------

/**
 * Named compiler configurations. `current` is the shipping default; every
 * other entry is an experimental flag combination. Adding a variant here is
 * all it takes to get it into the comparison table.
 */
export const VARIANTS: Record<string, CompileOptions> = {
  current: {},
  'ec-pool': { ecConstantPool: true },
  liveness: { schedulerMode: 'liveness' },
  both: { ecConstantPool: true, schedulerMode: 'liveness' },
};

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

export interface FixtureMetrics extends ScriptMetrics {
  fixture: string;
  /** Where the bytes came from: the checked-in golden or a live compile. */
  source: 'golden' | 'compiled';
}

export function measureGolden(fixture: string, hexPath: string): FixtureMetrics {
  const hex = readFileSync(hexPath, 'utf8').replace(/\s+/g, '');
  return { fixture, source: 'golden', ...analyzeScriptHex(hex) };
}

export function measureCompiled(
  fixture: string,
  sourcePath: string,
  options: CompileOptions,
): FixtureMetrics {
  const source = readFileSync(sourcePath, 'utf8');
  const result = compile(source, { ...options, fileName: sourcePath });
  if (!result.success || result.scriptHex === undefined) {
    const errs = result.diagnostics.filter(d => d.severity === 'error').map(d => d.message);
    throw new Error(`compile failed for '${fixture}': ${errs.join('; ') || 'no scriptHex'}`);
  }
  return { fixture, source: 'compiled', ...analyzeScriptHex(result.scriptHex) };
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

const REPORT_CATEGORIES: ByteCategory[] = [
  'const-push', 'stack-shuffle', 'arithmetic', 'bytes', 'crypto',
  'small-int-push', 'control', 'other',
];

function pct(part: number, whole: number): string {
  if (whole === 0) return '0.0%';
  return `${((100 * part) / whole).toFixed(1)}%`;
}

export function formatTable(rows: FixtureMetrics[]): string {
  const sorted = [...rows].sort((a, b) => b.scriptBytes - a.scriptBytes);
  const head = ['fixture', 'bytes', 'ops', ...REPORT_CATEGORIES];
  const lines = [
    `| ${head.join(' | ')} |`,
    `|${head.map((_, i) => (i === 0 ? '---' : '---:')).join('|')}|`,
  ];
  for (const r of sorted) {
    const cells = REPORT_CATEGORIES.map(c => {
      const v = r.categories[c];
      return v === 0 ? '—' : `${v} (${pct(v, r.scriptBytes)})`;
    });
    lines.push(`| ${r.fixture} | ${r.scriptBytes} | ${r.opcodeCount} | ${cells.join(' | ')} |`);
  }
  return lines.join('\n');
}

/** Per-fixture detail: the constants that dominate, and the opcode histogram. */
export function formatDetail(m: FixtureMetrics, topN = 8): string {
  const out: string[] = [];
  out.push(`### ${m.fixture} — ${m.scriptBytes} bytes, ${m.opcodeCount} ops (${m.source})`);
  out.push('');
  out.push('| category | bytes | share |');
  out.push('|---|---:|---:|');
  for (const c of REPORT_CATEGORIES) {
    const v = m.categories[c];
    if (v > 0) out.push(`| ${c} | ${v} | ${pct(v, m.scriptBytes)} |`);
  }
  out.push('');
  if (m.constants.length > 0) {
    out.push('| repeated constant | size | pushes | total bytes | share |');
    out.push('|---|---:|---:|---:|---:|');
    for (const c of m.constants.slice(0, topN)) {
      const label = c.hex.length > 24 ? `${c.hex.slice(0, 20)}…` : c.hex;
      out.push(`| \`${label}\` | ${c.hex.length / 2} B | ${c.count} | ${c.bytes} | ${pct(c.bytes, m.scriptBytes)} |`);
    }
    out.push('');
  }
  const ops = Object.entries(m.opcodes).sort((a, b) => b[1] - a[1]).slice(0, topN);
  out.push(`Top opcodes: ${ops.map(([k, v]) => `${k}×${v}`).join(', ')}`);
  return out.join('\n');
}

/** Side-by-side variant comparison for one fixture set. */
export function formatComparison(
  variantNames: string[],
  byVariant: Map<string, Map<string, FixtureMetrics>>,
): string {
  const base = variantNames[0]!;
  const fixtures = [...(byVariant.get(base)?.keys() ?? [])]
    .sort((a, b) => (byVariant.get(base)!.get(b)!.scriptBytes) - (byVariant.get(base)!.get(a)!.scriptBytes));
  const head = ['fixture', ...variantNames.map(v => (v === base ? `${v} (base)` : `${v}`)), 'delta'];
  const lines = [
    `| ${head.join(' | ')} |`,
    `|${head.map((_, i) => (i === 0 ? '---' : '---:')).join('|')}|`,
  ];
  for (const fx of fixtures) {
    const baseBytes = byVariant.get(base)!.get(fx)!.scriptBytes;
    const cells = variantNames.map(v => {
      const m = byVariant.get(v)?.get(fx);
      return m ? String(m.scriptBytes) : '—';
    });
    const last = byVariant.get(variantNames[variantNames.length - 1]!)?.get(fx);
    const delta = last && baseBytes > 0
      ? `${(((last.scriptBytes - baseBytes) / baseBytes) * 100).toFixed(1)}%`
      : '—';
    lines.push(`| ${fx} | ${cells.join(' | ')} | ${delta} |`);
  }
  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

interface Args {
  json?: string;
  fixture?: string;
  detail: boolean;
  compileMode: boolean;
  compare: string[];
  top: number;
}

export function parseArgs(argv: string[]): Args {
  const args: Args = { detail: false, compileMode: false, compare: [], top: 8 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--json') args.json = argv[++i];
    else if (a === '--fixture') args.fixture = argv[++i];
    else if (a === '--detail') args.detail = true;
    else if (a === '--compile') args.compileMode = true;
    else if (a === '--compare') { args.compare = (argv[++i] ?? '').split(',').filter(Boolean); args.compileMode = true; }
    else if (a === '--top') args.top = Number(argv[++i]);
    else if (a === '--help' || a === '-h') { args.detail = false; printHelp(); process.exit(0); }
    else throw new Error(`script-metrics: unknown argument '${a}'`);
  }
  return args;
}

function printHelp(): void {
  console.log(`
script-metrics — where do a fixture's script bytes go?

  --fixture <name>       measure one fixture instead of all
  --detail               per-fixture category / constant / opcode breakdown
  --compile              recompile from .runar.ts instead of reading the golden
  --compare a,b,c        compile under several named variants and diff (implies --compile)
  --json <path>          write machine-readable results
  --top <n>              rows in the constant / opcode lists (default 8)

Variants available: ${Object.keys(VARIANTS).join(', ')}
`.trim());
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const fixtures = discoverFixtures();
  const selected = args.fixture
    ? new Map(fixtures.has(args.fixture) ? [[args.fixture, fixtures.get(args.fixture)!]] : [])
    : fixtures;
  if (selected.size === 0) {
    throw new Error(`no fixtures selected${args.fixture ? ` (unknown fixture '${args.fixture}')` : ''}`);
  }

  if (args.compare.length > 0) {
    for (const name of args.compare) {
      if (!(name in VARIANTS)) {
        throw new Error(`unknown variant '${name}'. Known: ${Object.keys(VARIANTS).join(', ')}`);
      }
    }
    const byVariant = new Map<string, Map<string, FixtureMetrics>>();
    const skipped: string[] = [];
    for (const name of args.compare) {
      const perFixture = new Map<string, FixtureMetrics>();
      for (const [fx] of selected) {
        const src = tsSourcePath(fx);
        if (src === null) { if (name === args.compare[0]) skipped.push(fx); continue; }
        perFixture.set(fx, measureCompiled(fx, src, VARIANTS[name]!));
      }
      byVariant.set(name, perFixture);
    }
    console.log(formatComparison(args.compare, byVariant));
    if (skipped.length > 0) {
      // Never silently drop a fixture from a size report.
      console.log(`\n_Skipped (no .runar.ts source): ${skipped.join(', ')}_`);
    }
    if (args.json) {
      const payload = Object.fromEntries(
        [...byVariant].map(([v, m]) => [v, Object.fromEntries(m)]),
      );
      writeFileSync(args.json, `${JSON.stringify(payload, null, 2)}\n`);
    }
    return;
  }

  const rows: FixtureMetrics[] = [];
  const skipped: string[] = [];
  for (const [fx, hexPath] of selected) {
    if (args.compileMode) {
      const src = tsSourcePath(fx);
      if (src === null) { skipped.push(fx); continue; }
      rows.push(measureCompiled(fx, src, VARIANTS.current!));
    } else {
      rows.push(measureGolden(fx, hexPath));
    }
  }

  if (args.detail) {
    for (const r of [...rows].sort((a, b) => b.scriptBytes - a.scriptBytes)) {
      console.log(formatDetail(r, args.top));
      console.log('');
    }
  } else {
    console.log(formatTable(rows));
  }
  if (skipped.length > 0) {
    console.log(`\n_Skipped (no .runar.ts source): ${skipped.join(', ')}_`);
  }
  if (args.json) {
    writeFileSync(args.json, `${JSON.stringify(rows, null, 2)}\n`);
  }
}

const isMain = process.argv[1] !== undefined
  && resolve(process.argv[1]).endsWith(join('runner', 'script-metrics.ts'));
if (isMain) {
  try {
    main();
  } catch (err) {
    console.error(`script-metrics: ${(err as Error).message}`);
    process.exit(1);
  }
}

export { REPO_ROOT };
