// INTERPRETER-ONLY: spendability covered by conformance/witnesses/real-crypto/branch-merged-locals.json
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TestContract } from 'runar-testing';

/**
 * R-106 — `branch-merged-locals` had no test in any of the nine formats, and it
 * is one of the three branch-lifting shapes behind the 2026-08 fund-safety
 * miscompiles (the PALMER-1 family).
 *
 * The shape: two locals seeded from state, each reassigned on ONE arm of a
 * branch, then both handed to `addOutput`. The failure mode it guards is a
 * continuation that commits the WRONG merged values — a script that still
 * verifies while binding the wrong state, which is precisely the class a
 * byte-parity gate cannot see (all seven tiers would merge identically wrong)
 * and a verdict-only oracle cannot see either (both engines accept).
 *
 * So these assertions are about VALUES, not acceptance.
 */
const __dirname = dirname(fileURLToPath(import.meta.url));
const FILE = 'BranchMergedLocals.runar.ts';
const source = readFileSync(join(__dirname, FILE), 'utf8');

/**
 * The new values live in the EXPLICIT `addOutput`, not in the properties — the
 * method never assigns `this.a` / `this.b`. Reading `c.state` here would report
 * the constructor values on every path and pass no matter what the merge did,
 * which is the vacuity this fixture most needs to avoid.
 */
function continuation(r: { success: boolean; error?: string; outputs: Record<string, unknown>[] }) {
  expect(r.success, r.error).toBe(true);
  expect(r.outputs.length, 'the explicit addOutput must produce an output').toBeGreaterThan(0);
  return r.outputs[0]!;
}

describe('BranchMergedLocals (merged locals must reach addOutput intact)', () => {
  it('toFirst > 0 writes the first slot and carries the second unchanged', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n }, FILE);
    const out = continuation(c.call('bid', { amount: 77n, toFirst: 1n }));
    expect(out.a).toBe(77n);
    expect(out.b, 'the untouched arm must carry b through unchanged').toBe(2n);
  });

  it('toFirst <= 0 writes the second slot and carries the first unchanged', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n }, FILE);
    const out = continuation(c.call('bid', { amount: 77n, toFirst: 0n }));
    expect(out.a, 'the untouched arm must carry a through unchanged').toBe(1n);
    expect(out.b).toBe(77n);
  });

  it('a negative selector takes the same arm as zero', () => {
    const c = TestContract.fromSource(source, { a: 5n, b: 6n }, FILE);
    const out = continuation(c.call('bid', { amount: 9n, toFirst: -1n }));
    expect(out.a).toBe(5n);
    expect(out.b).toBe(9n);
  });

  it('the two arms do not both fire', () => {
    const c = TestContract.fromSource(source, { a: 1n, b: 2n }, FILE);
    const out = continuation(c.call('bid', { amount: 77n, toFirst: 1n }));
    expect(
      [out.a, out.b],
      'if both merged locals took the new value, the branch merge collapsed',
    ).toEqual([77n, 2n]);
  });
});
