/**
 * One-shot script: emit canonical analyzer-report goldens for the 8
 * conformance fixtures listed in `spec/script-analyzer-format.md` §13.
 *
 * Reads `conformance/tests/<name>/expected-script.hex`, runs the TS
 * reference `analyzeScript`, and writes
 * `conformance/analyzer/<name>/expected-analyzer-report.json` with the
 * exact formatting rules in spec §3.5.
 *
 * Usage (from repo root):
 *   pnpm --filter runar-testing exec tsx \
 *     conformance/analyzer/scripts/generate-goldens.ts
 *
 * Or with workspace deps already linked:
 *   cd conformance && npx tsx analyzer/scripts/generate-goldens.ts
 *
 *   --check                 re-derive reports and fail on drift (no write)
 *   --root <dir>            treat <dir> as the repo root (tests)
 *   --fixtures a,b          restrict to named fixtures
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeScript } from '../../../packages/runar-testing/src/analyzer/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_REPO_ROOT = join(__dirname, '..', '..', '..');

const FIXTURES = [
  'basic-p2pkh',
  'escrow',
  'stateful-counter',
  'auction',
  'covenant-vault',
  'ec-demo',
  'schnorr-zkp',
  'if-else',
];

// ---------------------------------------------------------------------------
// Spec-compliant JSON emission
// ---------------------------------------------------------------------------

// Ordered finding keys per spec §3.2.
const FINDING_KEY_ORDER = ['severity', 'code', 'message', 'offset', 'opcode', 'path'] as const;
const PATH_KEY_ORDER = ['id', 'description', 'branchChoices', 'reachable', 'hasCheckSig', 'stackDepthAtEnd'] as const;
const SUMMARY_KEY_ORDER = ['totalPaths', 'reachablePaths', 'pathsWithCheckSig', 'pathsWithoutCheckSig', 'maxStackDepth', 'scriptSizeBytes'] as const;
const TOP_KEY_ORDER = ['script', 'scriptSize', 'findings', 'paths', 'summary'] as const;

function reorder<T extends Record<string, unknown>>(obj: T, order: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of order) {
    if (k in obj && obj[k] !== undefined) out[k] = obj[k];
  }
  return out;
}

function buildReport(result: ReturnType<typeof analyzeScript>): Record<string, unknown> {
  const orderedFindings = result.findings.map((f) => reorder(f as unknown as Record<string, unknown>, FINDING_KEY_ORDER));
  const orderedPaths = result.paths.map((p) => reorder(p as unknown as Record<string, unknown>, PATH_KEY_ORDER));
  const orderedSummary = reorder(result.summary as unknown as Record<string, unknown>, SUMMARY_KEY_ORDER);
  return reorder(
    {
      script: result.script,
      scriptSize: result.scriptSize,
      findings: orderedFindings,
      paths: orderedPaths,
      summary: orderedSummary,
    },
    TOP_KEY_ORDER,
  );
}

// JSON.stringify with 2-space indent preserves insertion order on plain
// objects (ES2015+). Final newline per spec §3.5.
function emit(obj: unknown): string {
  return JSON.stringify(obj, null, 2) + '\n';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

interface CliArgs {
  checkOnly: boolean;
  root: string;
  fixtures: string[];
}

function parseArgs(argv: string[]): CliArgs {
  let checkOnly = false;
  let root = DEFAULT_REPO_ROOT;
  let fixtures = [...FIXTURES];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--check') checkOnly = true;
    else if (a === '--root' && i + 1 < argv.length) root = argv[++i]!;
    else if (a === '--fixtures' && i + 1 < argv.length) {
      fixtures = argv[++i]!.split(',').map((s) => s.trim()).filter(Boolean);
    } else if (a === '--help' || a === '-h') {
      console.log(
        'Usage: generate-goldens.ts [--check] [--root dir] [--fixtures a,b]',
      );
      process.exit(0);
    }
  }
  return { checkOnly, root, fixtures };
}

function deriveReport(root: string, name: string): { outPath: string; text: string; scriptSize: number; findings: number; paths: number } {
  const hexPath = join(root, 'conformance', 'tests', name, 'expected-script.hex');
  const outPath = join(root, 'conformance', 'analyzer', name, 'expected-analyzer-report.json');
  if (!existsSync(hexPath)) {
    throw new Error(`MISSING hex: ${hexPath}`);
  }
  const hex = readFileSync(hexPath, 'utf8').trim();
  const result = analyzeScript(hex);
  const report = buildReport(result);
  return {
    outPath,
    text: emit(report),
    scriptSize: result.scriptSize,
    findings: result.findings.length,
    paths: result.paths.length,
  };
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const drifted: string[] = [];
  const missing: string[] = [];

  for (const name of args.fixtures) {
    let derived: ReturnType<typeof deriveReport>;
    try {
      derived = deriveReport(args.root, name);
    } catch (err: any) {
      console.error(`[generate-goldens] ${err.message ?? err}`);
      missing.push(name);
      continue;
    }

    if (args.checkOnly) {
      if (!existsSync(derived.outPath)) {
        console.error(`[generate-goldens] MISSING report: ${derived.outPath}`);
        drifted.push(name);
        continue;
      }
      const existing = readFileSync(derived.outPath, 'utf8');
      if (existing !== derived.text) {
        console.error(
          `[generate-goldens] DRIFT: ${name} (report lags expected-script.hex)`,
        );
        drifted.push(name);
      } else {
        console.log(
          `[generate-goldens] ${name}: ok (${derived.scriptSize} bytes)`,
        );
      }
      continue;
    }

    mkdirSync(join(args.root, 'conformance', 'analyzer', name), { recursive: true });
    writeFileSync(derived.outPath, derived.text);
    console.log(
      `[generate-goldens] ${name}: ${derived.scriptSize} bytes, ` +
        `${derived.findings} finding(s), ${derived.paths} path(s) -> ${derived.outPath}`,
    );
  }

  if (missing.length > 0 || (args.checkOnly && drifted.length > 0)) {
    if (args.checkOnly && drifted.length > 0) {
      console.error(
        `\nanalyzer goldens stale: ${drifted.join(', ')}\n` +
          'Re-run without --check, review the diff, and commit.',
      );
    }
    process.exit(1);
  }
  if (args.checkOnly) {
    console.log('analyzer goldens match current expected-script.hex');
  }
}

main();
