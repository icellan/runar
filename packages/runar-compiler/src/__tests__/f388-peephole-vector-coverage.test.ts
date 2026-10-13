/**
 * F-388 / CL-GAP-004 — `optimizer/test-vectors.json` covered only 11 of the
 * 25 (then 28) rules declared in `optimizer/peephole-rules.json`, and one
 * vector was misnamed (`sha256-sha256-to-hash256`) so it matched no rule at
 * all — the rule is named `sha256-sha256`.
 *
 * `loadTestVectors()` (see `rule-loader.ts`) had no caller anywhere in the
 * repo before this test, same story as R-139's `loadPeepholeRules()`: a file
 * that calls itself a coverage fixture and is checked by nothing. This test
 * is that check, in two parts:
 *
 *  1. Name coverage — every declared rule has at least one correspondingly
 *     named vector, and every vector name matches a declared rule (so a
 *     future typo'd/renamed vector, or a vector for a deleted rule, is
 *     caught in both directions). "At least one" is deliberate: nothing here
 *     forbids a second vector for the same rule, so no 1:1 count assertion.
 *  2. Behavioral fidelity — each vector's "before" op-sequence is run
 *     through the REAL `optimizeStackIR` (peephole.ts) and must produce
 *     exactly "after". This is what makes a vector load-bearing against
 *     peephole.ts: weakening or deleting a matcher there breaks every vector
 *     whose rule it implements (verified below by disabling the optimizer
 *     entirely, and by disabling one specific matcher).
 *
 *     This test does NOT grade `optimizer/peephole-rules.json`'s match/
 *     replace shape — it links a vector to the JSON by NAME only. A JSON
 *     rule whose shape drifts from peephole.ts without the vector's before/
 *     after changing to match would NOT be caught here; that triangle side
 *     (JSON shape vs. peephole.ts) is R-139's job
 *     (`r139-peephole-rules-json-parity.test.ts`). The three checks together
 *     — R-139 (JSON shape ↔ peephole.ts), this test's part 1 (JSON names ↔
 *     vector names), and this test's part 2 (vectors ↔ peephole.ts behavior)
 *     — close the triangle.
 */

import { describe, it, expect } from 'vitest';
import { loadPeepholeRules, loadTestVectors } from '../optimizer/rule-loader.js';
import { optimizeStackIR } from '../optimizer/peephole.js';
import type { StackOp } from '../ir/index.js';

const rules = loadPeepholeRules();
const vectors = loadTestVectors();

describe('F-388 every peephole-rules.json rule has a matching test-vectors.json entry', () => {
  it('declares a non-trivial rule and vector set (a vacuous check proves nothing)', () => {
    expect(rules.length).toBeGreaterThan(0);
    expect(vectors.length).toBeGreaterThan(0);
  });

  it('every rule name has at least one correspondingly-named vector', () => {
    const vectorNames = new Set(vectors.map((v) => v.name));
    const uncovered = rules.map((r) => r.name).filter((n) => !vectorNames.has(n));
    expect(
      uncovered,
      `these rules have no matching test-vectors.json entry:\n  ${uncovered.join('\n  ')}`,
    ).toEqual([]);
  });

  it('every vector name matches a declared rule — no vector name that joins nothing', () => {
    const ruleNames = new Set(rules.map((r) => r.name));
    const orphanVectors = vectors.map((v) => v.name).filter((n) => !ruleNames.has(n));
    expect(
      orphanVectors,
      `these test-vectors.json entries match no rule name in peephole-rules.json:\n  ${orphanVectors.join('\n  ')}`,
    ).toEqual([]);
  });

});

/**
 * JSON cannot represent a bigint, so push values round-trip as plain
 * numbers; convert them back to match the real `StackOp` shape
 * (`ir/stack-ir.ts`) and `peephole.ts` require (`typeof value === 'bigint'`),
 * exactly as the emitted Stack IR would.
 */
function toRealOps(raw: Record<string, unknown>[]): StackOp[] {
  return raw.map((o) => {
    const op = { ...o } as Record<string, unknown>;
    if (op.op === 'push' && typeof op.value === 'number') {
      op.value = BigInt(op.value as number);
    }
    return op as unknown as StackOp;
  });
}

describe('F-388 test-vectors.json "before"/"after" match the REAL optimizer, not just names', () => {
  it.each(vectors.map((v) => [v.name, v] as const))(
    '%s: optimizeStackIR(before) === after',
    (_name, vector) => {
      const before = toRealOps(vector.before);
      const after = toRealOps(vector.after);
      expect(optimizeStackIR(before)).toEqual(after);
    },
  );
});
