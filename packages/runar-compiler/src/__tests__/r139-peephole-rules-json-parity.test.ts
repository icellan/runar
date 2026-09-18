import { describe, it, expect } from 'vitest';
import { loadPeepholeRules, ruleNames } from '../optimizer/rule-loader.js';
import { PEEPHOLE_RULES } from '../optimizer/peephole-rules.js';

/**
 * R-139 / CL-BUG-018 — `optimizer/peephole-rules.json` shipped the naive 2-op
 * `OP_NOT OP_NOT → []` elimination that the C17 fix replaced.
 *
 * `OP_NOT OP_NOT` is boolean NORMALISATION, not numeric identity: on a
 * non-canonical operand (5, say) the pair yields 1 while deleting it leaves 5.
 * Both implementations know this — the TS table matches the 3-op
 * `OP_NUMEQUAL OP_NOT OP_NOT` window and `compilers/go/codegen/optimizer.go`
 * carries the same guard with `producesCanonicalBool` — and the JSON, which
 * presents itself as "the canonical rule definition shared across all four
 * compilers", still declared the unguarded pair.
 *
 * Nothing read the file: `grep -rn peephole-rules.json` outside the audit
 * artefacts matches only `rule-loader.ts`, whose three exports had no callers
 * anywhere in the repo (CL-GAP-005 / R-235). A rule table that claims to be the
 * porting source of truth and is validated by nothing is how the stale rule
 * survived the C17 fix — and the next tier ported from it would have
 * reintroduced an unsound elimination.
 *
 * This test is that validation, and it is also what makes the loader live.
 * It compares OP SHAPE rather than literals: the JSON const-fold family uses
 * symbolic `$a`/`$b` where the TS table carries representative constants for
 * its sweep harness, so literal equality would be noise. Op count and opcode
 * codes are what the not-not drift actually changed — 2 ops to 3.
 */

/** Op kinds and opcode codes only; literals and depths are deliberately out. */
type Op = { op: string; code?: string };
const shape = (ops: readonly Op[]): string =>
  ops.map((o) => (o.code ? `${o.op}:${o.code}` : o.op)).join(' ');

const jsonRules = loadPeepholeRules();
const tsRules = PEEPHOLE_RULES as unknown as Array<{
  name: string;
  pattern: Op[];
  replacement: Op[];
}>;

describe('R-139 optimizer/peephole-rules.json matches the implemented table', () => {
  it('the loader returns a non-empty rule set (a silently empty file proves nothing)', () => {
    expect(jsonRules.length).toBeGreaterThanOrEqual(20);
    expect(ruleNames().length).toBe(jsonRules.length);
  });

  it('declares the same number of rules as the TS implementation', () => {
    expect(jsonRules.length).toBe(tsRules.length);
  });

  it('every JSON rule has a TS rule with the same pattern AND replacement shape', () => {
    const tsByShape = new Map<string, string>();
    for (const r of tsRules) {
      tsByShape.set(`${shape(r.pattern)} => ${shape(r.replacement)}`, r.name);
    }
    const orphans = jsonRules
      .map((r) => ({
        name: r.name,
        key: `${shape(r.match as Op[])} => ${shape(r.replace as Op[])}`,
      }))
      .filter((r) => !tsByShape.has(r.key));
    expect(
      orphans,
      `these JSON rules match no implemented rule:\n` +
        orphans.map((o) => `  ${o.name}: ${o.key}`).join('\n') +
        `\nThe JSON is the porting source of truth; a rule here that no tier ` +
        `implements is a rule the next tier will implement wrongly.`,
    ).toEqual([]);
  });

  it('every implemented rule is declared in the JSON — no silent extras either', () => {
    const jsonShapes = new Set(
      jsonRules.map((r) => `${shape(r.match as Op[])} => ${shape(r.replace as Op[])}`),
    );
    const undeclared = tsRules
      .map((r) => ({ name: r.name, key: `${shape(r.pattern)} => ${shape(r.replacement)}` }))
      .filter((r) => !jsonShapes.has(r.key));
    expect(
      undeclared,
      `these implemented rules are absent from the JSON:\n` +
        undeclared.map((o) => `  ${o.name}: ${o.key}`).join('\n'),
    ).toEqual([]);
  });

  it('the not-not rule is the GUARDED 3-op form, in both places', () => {
    const json = jsonRules.find((r) => /not-not/.test(r.name));
    expect(json, 'the not-not rule vanished from the JSON').toBeDefined();
    expect(
      shape(json!.match as Op[]),
      'the JSON is back to the unguarded 2-op OP_NOT OP_NOT elimination, which ' +
        'deletes the pair on a non-canonical operand and changes the value',
    ).toBe('opcode:OP_NUMEQUAL opcode:OP_NOT opcode:OP_NOT');
    expect(shape(json!.replace as Op[])).toBe('opcode:OP_NUMEQUAL');

    const ts = tsRules.find((r) => r.name === 'not-not-elim');
    expect(shape(ts!.pattern)).toBe('opcode:OP_NUMEQUAL opcode:OP_NOT opcode:OP_NOT');
  });

  it('no rule deletes a bare OP_NOT OP_NOT pair', () => {
    const unguarded = jsonRules.filter(
      (r) => shape(r.match as Op[]) === 'opcode:OP_NOT opcode:OP_NOT',
    );
    expect(unguarded.map((r) => r.name)).toEqual([]);
  });
});
