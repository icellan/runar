/**
 * Coverage matrix: run the decompiler against every example contract and
 * every conformance fixture, record per-row outcome + recovery path,
 * write the result to coverage.json. Compare against coverage-baseline.json;
 * CI fails only on regression.
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
 * Run: pnpm --filter runar-decompiler run coverage
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

function tryExample(file: string): Row {
  const id = relative(EXAMPLES_DIR, file).replace(/\.runar\.ts$/, '');
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

function main() {
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

  const out = {
    generatedAt: new Date().toISOString(),
    summary,
    pathBreakdown,
    rows: rows.map(r => ({
      id: r.id,
      outcome: r.outcome,
      recoveryPath: r.recoveryPath,
      detail: r.detail,
    })),
  };

  const outPath = resolve(__dirname, '..', 'coverage.json');
  writeFileSync(outPath, JSON.stringify(out, null, 2) + '\n', 'utf8');

  console.log('Coverage matrix:');
  for (const k of Object.keys(summary) as Outcome[]) console.log(`  ${k}: ${summary[k]}`);
  console.log('Recovery path breakdown:');
  for (const k of Object.keys(pathBreakdown) as RecoveryPath[]) console.log(`  ${k}: ${pathBreakdown[k]}`);
  console.log(`  → ${outPath}`);
}

main();
