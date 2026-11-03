import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-321 — seven-tier gate: a typecheck diagnostic never echoes unbounded
 * source text.
 *
 * A 4 MiB type annotation made the Go tier print a ~4 MiB error (found by
 * N-311). Every tier now caps a typecheck message at 1024 characters and ends
 * it with `...(N more bytes elided)`; real messages are far shorter, so ordinary
 * diagnostics are unchanged.
 *
 * Proves, for every available tier: a 1 MB undefined identifier in an
 * expression is refused with a diagnostic that carries the elision marker and
 * is far smaller than the input; a 1 MB flat type annotation is refused (or, in
 * the tiers that normalise unknown type names, accepted) with a diagnostic that
 * is never larger than 16 KB; a short undefined identifier is echoed verbatim.
 * Does not prove: every individual echo site (the cap sits at each tier's
 * diagnostic sink), or the wording of the other typecheck messages.
 */

const CASE_TIMEOUT_MS = 600_000;
const MARKER = /\.\.\.\(\d+ more bytes elided\)/;
const BIG = 1 << 20;
const BOUND = 16 * 1024;

const HEAD = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = {V};\n assert(q == this.t);\n }\n}\n";

function src(type: string, value: string): string {
  return HEAD.replace('{T}', type).replace('{V}', value);
}

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n321-echo-'));
});

let seq = 0;
function write(text: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'P.runar.ts');
  writeFileSync(p, text);
  return p;
}

describe('N-321 seven-tier bounded typecheck diagnostics', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  it('a 1 MB undefined identifier: every tier refuses with an elided diagnostic', () => {
    const file = write(src('bigint', 'T'.repeat(BIG)));
    for (const tier of TIERS) {
      const { verdict, diag } = judge(tier, file);
      expect(verdict, `${tier.id} accepted an undefined identifier`).toBe('rejected');
      expect(diag, `${tier.id}: no elision marker`).toMatch(MARKER);
      expect(diag.length, `${tier.id}: ${diag.length} byte diagnostic`).toBeLessThan(BOUND);
    }
  }, CASE_TIMEOUT_MS);

  it('a 1 MB flat type annotation: no tier echoes it unbounded', () => {
    const file = write(src('T'.repeat(BIG), 'a'));
    for (const tier of TIERS) {
      const { diag } = judge(tier, file);
      expect(diag.length, `${tier.id}: ${diag.length} byte diagnostic`).toBeLessThan(BOUND);
    }
  }, CASE_TIMEOUT_MS);

  it('a short undefined identifier is echoed verbatim', () => {
    const file = write(src('bigint', 'nope'));
    for (const tier of TIERS) {
      const { verdict, diag } = judge(tier, file);
      expect(verdict, `${tier.id} accepted an undefined identifier`).toBe('rejected');
      expect(diag, `${tier.id}: ordinary diagnostic changed`).toContain("'nope'");
      expect(diag).not.toMatch(MARKER);
    }
  }, CASE_TIMEOUT_MS);
});
