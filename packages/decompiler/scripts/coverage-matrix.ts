/**
 * Coverage matrix: run the decompiler against every example contract and
 * every conformance fixture, record per-row outcome + recovery path, and
 * compare the result against the recorded coverage.json. Any drift — a row
 * whose outcome or recovery path moved, a row that appeared, a row that
 * disappeared — exits non-zero.
 *
 * The header used to claim it compared against coverage-baseline.json. It
 * did not: the script had no comparison and no failure path of any kind
 * (`grep -nE 'exit|throw|baseline'` matched only that sentence), so the
 * `Decompiler coverage matrix` CI step could not fail and the checked-in
 * coverage.json drifted 7 rows stale unnoticed.
 *
 * coverage.json is the recorded expectation rather than coverage-baseline.json
 * because it pins strictly more: every row's recoveryPath and detail string,
 * plus the `skipped` rows that the baseline's vocabulary has no place for. It
 * is also the artifact CI already uploads. The baseline stays what the Tier 1
 * / Tier 2 round-trip tests gate on — they classify differently from this
 * script (no artifact-derived options), so the two are deliberately not
 * cross-compared.
 *
 * This is the same drift-check shape as the `Fingerprint DB drift check` and
 * `Templates manifest drift check` steps beside it in CI, but self-contained:
 * the comparison is in the script, so the existing CI step gains a failure
 * path without a wrapper. `generatedAt` is preserved when nothing moved
 * semantically (as scripts/generate-templates.ts does) so a re-run never
 * produces a timestamp-only diff.
 *
 * Run: pnpm --filter runar-decompiler run coverage          (write + check)
 *      pnpm --filter runar-decompiler run coverage -- --check [path]  (check only)
 *
 * Two axes are reported:
 *   - outcome:      byte-match / byte-diff / compile-error / parse-error
 *   - recoveryPath: which layer produced the candidate (template /
 *                   assert-recognizer / raw_script). When the asm primitive
 *                   landed, the raw_script floor closed the last gap.
 *
 * Recurring raw_script-only contracts are the candidate set for future
 * fingerprint additions (real symbolic recovery makes the matrix shift
 * left toward `template` / `assert-recognizer`).
 *
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';
import type { RecoveryPath } from '../src/types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const REPO_ROOT = resolve(__dirname, '..', '..', '..');
const EXAMPLES_DIR = resolve(REPO_ROOT, 'examples', 'ts');
const FIXTURES_DIR = resolve(REPO_ROOT, 'conformance', 'sdk-codegen', 'fixtures');

type Outcome = 'byte-match' | 'byte-diff' | 'compile-error' | 'parse-error' | 'skipped';

interface Row {
  id: string;
  source: string;
  outcome: Outcome;
  recoveryPath?: RecoveryPath;
  detail?: string;
}

function listContractFiles(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  function walk(d: string) {
    for (const entry of readdirSync(d)) {
      const full = resolve(d, entry);
      const s = statSync(full);
      if (s.isDirectory()) walk(full);
      else if (entry.endsWith('.runar.ts')) out.push(full);
    }
  }
  walk(dir);
  return out.sort();
}

// Examples whose compiled script drives the symbolic-execution lifter into
// pathological (super-linear) runtime — minutes-to-hours each. Mirrors the
// PATHOLOGICAL_DECOMPILE set in __tests__/roundtrip.test.ts: the parameterized
// SLH-DSA "naive INSECURE" pedagogy contracts unroll into enormous hash-chain
// scripts, while r1-k1-wallet fully unrolls a P-256 verifier. The trigger is
// script *structure*, not raw size (p384-wallet ~1.95 MB decompiles in <1s).
// Recorded as 'skipped' so the matrix completes in seconds instead of hours;
// the base post-quantum-slhdsa-naive-INSECURE (128s) is fast and stays measured.
const PATHOLOGICAL_DECOMPILE: ReadonlySet<string> = new Set([
  'r1-k1-wallet/R1K1Wallet',
  'post-quantum-slhdsa-naive-INSECURE-128f/PostQuantumSLHDSANaiveInsecure128f',
  'post-quantum-slhdsa-naive-INSECURE-192f/PostQuantumSLHDSANaiveInsecure192f',
  'post-quantum-slhdsa-naive-INSECURE-192s/PostQuantumSLHDSANaiveInsecure192s',
  'post-quantum-slhdsa-naive-INSECURE-256f/PostQuantumSLHDSANaiveInsecure256f',
  'post-quantum-slhdsa-naive-INSECURE-256s/PostQuantumSLHDSANaiveInsecure256s',
]);

function tryExample(file: string): Row {
  const id = relative(EXAMPLES_DIR, file).replace(/\.runar\.ts$/, '');
  if (PATHOLOGICAL_DECOMPILE.has(id)) {
    return { id, source: file, outcome: 'skipped', detail: 'pathological symexec runtime — see roundtrip.test.ts PATHOLOGICAL_DECOMPILE' };
  }
  const source = readFileSync(file, 'utf8');
  const r = compile(source, { fileName: basename(file) });
  if (!r.success || !r.scriptHex) {
    const errs = r.diagnostics.filter(d => d.severity === 'error').map(d => d.message).join('; ');
    return { id, source: file, outcome: 'compile-error', detail: errs };
  }
  try {
    // Pass artifact-derived info so the stateful path (and constructor-slot
    // recovery) is exercised — that's the realistic real-world deployment
    // scenario: callers always have the artifact alongside the bytes.
    const result = decompile(hexToBytes(r.scriptHex), {
      constructorSlots: r.artifact?.constructorSlots,
      stateFields: r.artifact?.stateFields,
      codeSeparatorIndex: r.artifact?.codeSeparatorIndex,
      codeSeparatorIndices: r.artifact?.codeSeparatorIndices,
      anf: r.artifact?.anf,
    });
    if (result.ok) return { id, source: file, outcome: 'byte-match', recoveryPath: result.recoveryPath };
    return {
      id,
      source: file,
      outcome: 'byte-diff',
      recoveryPath: result.recoveryPath,
      detail: result.diff ? `divergeAt=${result.diff.divergenceOffset}` : 'no diff',
    };
  } catch (e: unknown) {
    return { id, source: file, outcome: 'parse-error', detail: e instanceof Error ? e.message : String(e) };
  }
}

function tryFixture(file: string): Row {
  const id = `fixture/${basename(file, '.json')}`;
  const raw = JSON.parse(readFileSync(file, 'utf8')) as { script: string };
  try {
    const result = decompile(hexToBytes(raw.script));
    if (result.ok) return { id, source: file, outcome: 'byte-match', recoveryPath: result.recoveryPath };
    return {
      id,
      source: file,
      outcome: 'byte-diff',
      recoveryPath: result.recoveryPath,
      detail: result.diff ? `divergeAt=${result.diff.divergenceOffset}` : 'no diff',
    };
  } catch (e: unknown) {
    return { id, source: file, outcome: 'parse-error', detail: e instanceof Error ? e.message : String(e) };
  }
}

interface Matrix {
  generatedAt: string;
  summary: Record<Outcome, number>;
  pathBreakdown: Record<RecoveryPath, number>;
  rows: { id: string; outcome: Outcome; recoveryPath?: RecoveryPath; detail?: string }[];
}

/** Everything except the timestamp — the part a re-run must reproduce exactly. */
function semanticKey(m: Pick<Matrix, 'summary' | 'pathBreakdown' | 'rows'>): string {
  return JSON.stringify({ summary: m.summary, pathBreakdown: m.pathBreakdown, rows: m.rows });
}

function readMatrix(path: string): Matrix | null {
  if (!existsSync(path)) return null;
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as Matrix;
  } catch {
    return null;
  }
}

/** Human-readable account of what moved. Empty ⇒ no drift. */
function describeDrift(prev: Matrix | null, next: Matrix): string[] {
  if (!prev) return ['no recorded coverage matrix to compare against (absent or unparseable)'];
  if (semanticKey(prev) === semanticKey(next)) return [];

  const msgs: string[] = [];
  const p = new Map(prev.rows.map(r => [r.id, r]));
  const n = new Map(next.rows.map(r => [r.id, r]));
  const show = (r: { outcome: Outcome; recoveryPath?: RecoveryPath }) =>
    `${r.outcome}/${r.recoveryPath ?? '-'}`;

  for (const [id, row] of n) {
    if (!p.has(id)) msgs.push(`  + ${id}: new row (${show(row)})`);
  }
  for (const [id, row] of p) {
    if (!n.has(id)) msgs.push(`  - ${id}: row disappeared (was ${show(row)})`);
  }
  for (const [id, row] of n) {
    const before = p.get(id);
    if (!before) continue;
    if (JSON.stringify(before) !== JSON.stringify(row)) {
      const detail = before.detail === row.detail ? '' : ` [detail: ${before.detail ?? '-'} → ${row.detail ?? '-'}]`;
      msgs.push(`  ~ ${id}: ${show(before)} → ${show(row)}${detail}`);
    }
  }
  if (msgs.length === 0) {
    // Rows agree but the derived totals do not — a bug in the aggregation.
    msgs.push('  ~ summary / pathBreakdown differ while every row agrees');
  }
  return msgs;
}

function main() {
  const argv = process.argv.slice(2);
  const checkOnly = argv.includes('--check');
  const expectedPath = argv.filter(a => !a.startsWith('--'))[0]
    ?? resolve(__dirname, '..', 'coverage.json');

  const rows: Row[] = [];

  for (const f of listContractFiles(EXAMPLES_DIR)) {
    rows.push(tryExample(f));
  }
  if (existsSync(FIXTURES_DIR)) {
    for (const f of readdirSync(FIXTURES_DIR)) {
      if (f.endsWith('.json')) rows.push(tryFixture(resolve(FIXTURES_DIR, f)));
    }
  }

  const summary: Record<Outcome, number> = {
    'byte-match': 0,
    'byte-diff': 0,
    'compile-error': 0,
    'parse-error': 0,
    'skipped': 0,
  };
  const pathBreakdown: Record<RecoveryPath, number> = {
    'template': 0,
    'assert-recognizer': 0,
    'symexec': 0,
    'raw_script': 0,
  };
  for (const r of rows) {
    summary[r.outcome]++;
    if (r.recoveryPath) pathBreakdown[r.recoveryPath]++;
  }

  const computed = {
    summary,
    pathBreakdown,
    // Round-trip through JSON so the comparison sees exactly what a reader of
    // the file sees (`undefined` fields dropped, key order fixed).
    rows: JSON.parse(JSON.stringify(rows.map(r => ({
      id: r.id,
      outcome: r.outcome,
      recoveryPath: r.recoveryPath,
      detail: r.detail,
    })))) as Matrix['rows'],
  };

  const expected = readMatrix(expectedPath);
  const drift = describeDrift(expected, { generatedAt: '', ...computed });

  console.log('Coverage matrix:');
  for (const k of Object.keys(summary) as Outcome[]) console.log(`  ${k}: ${summary[k]}`);
  console.log('Recovery path breakdown:');
  for (const k of Object.keys(pathBreakdown) as RecoveryPath[]) console.log(`  ${k}: ${pathBreakdown[k]}`);

  const outPath = resolve(__dirname, '..', 'coverage.json');
  if (!checkOnly) {
    // Preserve the timestamp when nothing moved, so re-running never produces
    // a timestamp-only diff on a tracked file.
    const out: Matrix = {
      generatedAt: drift.length === 0 && expected ? expected.generatedAt : new Date().toISOString(),
      ...computed,
    };
    writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n', 'utf8');
    console.log(`  → ${outPath}${drift.length === 0 ? ' (unchanged)' : ''}`);
  }

  if (drift.length > 0) {
    console.error(`\nCoverage matrix drift vs ${expectedPath}:`);
    for (const m of drift) console.error(m);
    console.error(
      checkOnly
        ? '\nRe-run `pnpm --filter runar-decompiler run coverage` to refresh coverage.json, review the diff, and commit it.'
        : '\ncoverage.json has been refreshed above — review the diff and commit it, then re-run to confirm green.',
    );
    process.exit(1);
  }
}

main();
