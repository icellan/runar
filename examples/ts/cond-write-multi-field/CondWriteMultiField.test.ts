// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/cond-write-multi-field.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `cond-write-multi-field` had no test in any of the nine formats, and
 * it is one of the three branch-lifting shapes behind the 2026-08 fund-safety
 * miscompiles.
 *
 * The shape: TWO property writes inside ONE conditional arm, then an explicit
 * `addOutput` of both. The failure mode is a continuation that commits one
 * field's new value and the other's old one — a script that verifies while
 * binding a state nobody wrote. Acceptance says nothing about it; only the
 * values do.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'CondWriteMultiField.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

function continuation(r: { success: boolean; error?: string; outputs: Record<string, unknown>[] }) {
  expect(r.success, r.error).toBe(true);
  expect(r.outputs.length).toBeGreaterThan(0);
  return r.outputs[0]!;
}

describe('CondWriteMultiField (two writes in one arm)', () => {
  it('flag > 0: BOTH fields advance, by their own amounts', () => {
    const c = TestContract.fromSource(source, { a: 10n, b: 20n }, FILE);
    const out = continuation(c.call('bump', { flag: 1n }));
    expect(out.a).toBe(11n);
    expect(
      out.b,
      'b advances by 2, not by 1 and not at all — a lifted branch that reuses ' +
        "one arm's value for both fields lands exactly here",
    ).toBe(22n);
  });

  it('flag <= 0: NEITHER field advances', () => {
    const c = TestContract.fromSource(source, { a: 10n, b: 20n }, FILE);
    const out = continuation(c.call('bump', { flag: 0n }));
    expect(out.a).toBe(10n);
    expect(out.b).toBe(20n);
  });

  it('the arm is all-or-nothing', () => {
    const c = TestContract.fromSource(source, { a: 0n, b: 0n }, FILE);
    const taken = continuation(c.call('bump', { flag: 5n }));
    expect([taken.a, taken.b]).toEqual([1n, 2n]);

    const c2 = TestContract.fromSource(source, { a: 0n, b: 0n }, FILE);
    const skipped = continuation(c2.call('bump', { flag: -5n }));
    expect([skipped.a, skipped.b]).toEqual([0n, 0n]);
  });
});
