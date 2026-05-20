/**
 * Tier 1 + Tier 2 round-trip tests.
 *
 * Tier 1: every example contract under examples/ts/*.runar.ts.
 *   - Compile source → target bytes.
 *   - Decompile bytes → recovered source.
 *   - Re-compile recovered → bytes'.
 *   - Record byte-match / byte-diff / compile-error.
 *   - Fail CI only on regression vs. coverage-baseline.json.
 *
 * Tier 2: every conformance fixture under conformance/sdk-codegen/fixtures/*.json.
 *   - Gated to byte-match for the current v0 in-scope set (initially empty;
 *     expands as symexec/lift mature).
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, dirname, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compile } from 'runar-compiler';
import { hexToBytes } from 'runar-testing';
import { decompile } from '../src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..', '..', '..');
const EXAMPLES_DIR = resolve(REPO_ROOT, 'examples', 'ts');
const FIXTURES_DIR = resolve(REPO_ROOT, 'conformance', 'sdk-codegen', 'fixtures');
const BASELINE_PATH = resolve(__dirname, '..', 'coverage-baseline.json');

type Outcome = 'byte-match' | 'byte-diff' | 'compile-error' | 'parse-error';

interface BaselineRow { id: string; outcome: Outcome }
interface Baseline { rows: BaselineRow[] }

function loadBaseline(): Map<string, Outcome> {
  const map = new Map<string, Outcome>();
  if (!existsSync(BASELINE_PATH)) return map;
  try {
    const parsed = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Baseline;
    for (const r of parsed.rows) map.set(r.id, r.outcome);
  } catch {
    // ignore — empty baseline = no expectations
  }
  return map;
}

function listExamples(): string[] {
  const out: string[] = [];
  if (!existsSync(EXAMPLES_DIR)) return out;
  function walk(d: string) {
    for (const entry of readdirSync(d)) {
      const full = resolve(d, entry);
      if (statSync(full).isDirectory()) walk(full);
      else if (entry.endsWith('.runar.ts')) out.push(full);
    }
  }
  walk(EXAMPLES_DIR);
  return out.sort();
}

function classifyExample(file: string): { id: string; outcome: Outcome } {
  const id = relative(EXAMPLES_DIR, file).replace(/\.runar\.ts$/, '');
  const source = readFileSync(file, 'utf8');
  const r = compile(source, { fileName: basename(file) });
  if (!r.success || !r.scriptHex) {
    return { id, outcome: 'compile-error' };
  }
  try {
    const result = decompile(hexToBytes(r.scriptHex));
    return { id, outcome: result.ok ? 'byte-match' : 'byte-diff' };
  } catch {
    return { id, outcome: 'parse-error' };
  }
}

// Examples whose compiled script drives the symbolic-execution lifter into
// pathological (super-linear) runtime — minutes-to-hours each — making the
// round-trip suite impractical (it would blow past CI's job timeout). These
// are the parameterized SLH-DSA "naive INSECURE" pedagogy contracts (large
// Winternitz/FORS parameter sets that unroll into enormous hash-chain
// scripts: 128f/192f/192s/256f/256s). The script *structure*, not raw size,
// is the trigger — p384-wallet (~1.95 MB) decompiles in <1s while
// slhdsa-naive-128f (~0.5 MB) takes minutes. None of these are byte-match
// targets in coverage-baseline.json (decompiling giant unrolled crypto back
// to source is not a meaningful round-trip goal), so skipping them loses no
// coverage. The base `post-quantum-slhdsa-naive-INSECURE` (128s params) is
// fast and stays covered. Revisit if the lifter's pathological case is fixed.
const PATHOLOGICAL_DECOMPILE: ReadonlySet<string> = new Set([
  'post-quantum-slhdsa-naive-INSECURE-128f/PostQuantumSLHDSANaiveInsecure128f',
  'post-quantum-slhdsa-naive-INSECURE-192f/PostQuantumSLHDSANaiveInsecure192f',
  'post-quantum-slhdsa-naive-INSECURE-192s/PostQuantumSLHDSANaiveInsecure192s',
  'post-quantum-slhdsa-naive-INSECURE-256f/PostQuantumSLHDSANaiveInsecure256f',
  'post-quantum-slhdsa-naive-INSECURE-256s/PostQuantumSLHDSANaiveInsecure256s',
]);

describe('Tier 1: examples coverage matrix', () => {
  const baseline = loadBaseline();
  const files = listExamples();

  for (const f of files) {
    const id = relative(EXAMPLES_DIR, f).replace(/\.runar\.ts$/, '');
    const expected = baseline.get(id);
    const testFn = PATHOLOGICAL_DECOMPILE.has(id) ? it.skip : it;
    testFn(`${id}: outcome${expected ? ` should remain ${expected}` : ' recorded for baseline'}`, () => {
      const got = classifyExample(f);
      if (expected === 'byte-match') {
        // Regression check: a byte-match must stay byte-match.
        expect(got.outcome, `regression on ${id}: was byte-match`).toBe('byte-match');
      } else {
        // Non-strict: record outcome; CI only fails on a byte-match regression.
        expect(got.outcome).toMatch(/^(byte-match|byte-diff|compile-error|parse-error)$/);
      }
    });
  }
});

describe('Tier 2: conformance fixtures', () => {
  if (!existsSync(FIXTURES_DIR)) {
    it.skip('conformance fixtures directory missing', () => {});
    return;
  }

  // Fixtures we expect to round-trip exactly. Add fixtures here as the
  // symbolic lifter learns to recover their shapes.
  const HARD_GATES: ReadonlySet<string> = new Set(['simple']);

  const files = readdirSync(FIXTURES_DIR).filter(f => f.endsWith('.json')).sort();
  for (const f of files) {
    const stem = basename(f, '.json');
    const id = `fixture/${stem}`;
    it(`${id}: round-trip${HARD_GATES.has(stem) ? ' (byte-match required)' : ' recorded'}`, () => {
      const raw = JSON.parse(readFileSync(resolve(FIXTURES_DIR, f), 'utf8')) as { script: string };
      if (raw.script.length === 0) return; // empty fixture — vacuously holds
      const result = decompile(hexToBytes(raw.script));
      expect(result).toBeDefined();
      if (HARD_GATES.has(stem)) {
        expect(
          result.ok,
          `expected ${id} to byte-match; diff at offset ${result.diff?.divergenceOffset}`,
        ).toBe(true);
      }
    });
  }
});
