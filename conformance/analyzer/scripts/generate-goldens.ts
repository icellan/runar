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
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeScript } from '../../../packages/runar-testing/src/analyzer/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');

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
  const orderedFindings = result.findings.map((f) => reorder(f as Record<string, unknown>, FINDING_KEY_ORDER));
  const orderedPaths = result.paths.map((p) => reorder(p as Record<string, unknown>, PATH_KEY_ORDER));
  const orderedSummary = reorder(result.summary as Record<string, unknown>, SUMMARY_KEY_ORDER);
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

function main(): void {
  for (const name of FIXTURES) {
    const hexPath = join(REPO_ROOT, 'conformance', 'tests', name, 'expected-script.hex');
    const outDir = join(REPO_ROOT, 'conformance', 'analyzer', name);
    const outPath = join(outDir, 'expected-analyzer-report.json');

    if (!existsSync(hexPath)) {
      console.error(`[generate-goldens] MISSING: ${hexPath}`);
      process.exit(1);
    }

    const hex = readFileSync(hexPath, 'utf8').trim();
    const result = analyzeScript(hex);
    const report = buildReport(result);

    mkdirSync(outDir, { recursive: true });
    writeFileSync(outPath, emit(report));

    console.log(
      `[generate-goldens] ${name}: ${result.scriptSize} bytes, ` +
        `${result.findings.length} finding(s), ${result.paths.length} path(s) -> ${outPath}`,
    );
  }
}

main();
