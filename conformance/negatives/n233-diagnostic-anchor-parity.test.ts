import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-233 — tiers anchor the same diagnostic at the same AST NODE.
 *
 * N-078 made every tier print a 0-based column; this item is about which node
 * the column points at. The TS reference is the anchor (dispatcher decision).
 *
 * Converged here — N175-N179, the `.runar.go` ambiguous operator precedence
 * refusal (N-056). TS anchors it at the ambiguous binary expression, whose
 * position is its leftmost operand. Before this item Go and Rust, Python,
 * Ruby and Java printed the message with no location at all (Go's only
 * location was a follow-on "unsupported Go statement" at the statement), and
 * Zig pointed at the token after the expression. The expected column is
 * computed from the fixture text (`lineText.indexOf(anchor)`), never copied
 * from a compiler's output, and it is read from the line that carries the
 * precedence message, not from whatever location a tier prints first.
 *
 * Converged by N-463 — the `.runar.ts` typecheck refusals N15-N17 and
 * N200-N209. TS anchors each at the offending EXPRESSION: the left operand of
 * a non-bigint comparison (N15, a call `this.hp()`), the satoshis argument of
 * addOutput (N16, `this.blob`), the ternary (N17, its condition `f`), and the
 * re-consumed affine identifier (N200-N209, `sig`). Before N-463 Go, Python,
 * Ruby and Java anchored them at the enclosing statement, Rust at the method
 * header, and Zig printed no location at all, because their expression nodes
 * carried no source position. The message fragment is matched rather than the
 * full text because the tiers word these four messages slightly differently
 * (`Left`/`left`, Java's `'X' vs 'Y'`), which this item does not change.
 *
 * Still divergent — the ANCHOR_PENDING row below: a decision on the anchor is
 * needed because TS itself is inconsistent across surfaces (N220-N228: the
 * verifyRabinSig public-key refusal is at the call on `.runar.ts` but at the
 * method header on seven other surfaces). It is pinned as divergent so that
 * converging it fails here until its row moves into CASES.
 *
 * What this proves: for every CASES row every tier is present, refuses, and
 * prints the row's message at `<file>:<line>:<column of the anchor text>`.
 * What it does NOT prove: node parity for any other diagnostic, or for these
 * diagnostics on the eight non-`.runar.ts` surfaces (their parsers leave the
 * new expression locations empty and keep the old anchors); that a tier's
 * follow-on diagnostics (Go's "unsupported Go statement") agree; anchor
 * agreement for an ambiguous edge nested under a non-ambiguous parent, where
 * Go precedence and the C ladder pick different parent nodes; the other
 * members of the four families (right operands, unary operands,
 * addRawOutput/addDataOutput satoshis) beyond the one shape each row exercises.
 */

const TIERS = buildSourceTiers();
const PRECEDENCE = 'ambiguous operator precedence in .runar.go';
const AFFINE = "affine value 'sig' has already been consumed";

/**
 * [fixture, 1-based line, anchor text whose first character is the position,
 *  message fragment the located line must carry].
 */
const CASES: Array<[string, number, string, string]> = [
  ['N175-go-precedence-and-add.runar.go', 20, 'a & b + 1', PRECEDENCE],
  ['N176-go-precedence-add-shift.runar.go', 20, 'a + b << 2', PRECEDENCE],
  ['N177-go-precedence-or-add.runar.go', 20, 'a | b + d', PRECEDENCE],
  ['N178-go-precedence-and-eq.runar.go', 22, 'a & 255 == 15', PRECEDENCE],
  ['N179-go-precedence-shift-mul.runar.go', 20, 'a << b * d', PRECEDENCE],
  // N-463: the offending expression, not the statement or method.
  ['N15-unknown-operand-type.runar.ts', 36, 'this.hp() > x', "operand of '>' must be bigint"],
  ['N16-bytestring-satoshis.runar.ts', 47, 'this.blob,', 'first argument (satoshis) must be bigint'],
  ['N17-ternary-branch-types.runar.ts', 43, 'f ? this.blob', 'ranches have incompatible types'],
  // The second consumption of `sig` on every path is the refused one.
  ['N200-ts-affine-sig-then-arm-and-after-if.runar.ts', 20, 'sig,', AFFINE],
  ['N201-ts-affine-sig-else-arm-and-after-if.runar.ts', 22, 'sig,', AFFINE],
  ['N202-ts-affine-sig-both-arms-and-after-if.runar.ts', 23, 'sig,', AFFINE],
  ['N203-ts-affine-sig-nested-arm-and-after-if.runar.ts', 25, 'sig,', AFFINE],
  ['N204-ts-affine-sig-alias-arm-and-after-if.runar.ts', 24, 'sig,', AFFINE],
  ['N205-ts-affine-sig-before-if-and-in-arm.runar.ts', 19, 'sig,', AFFINE],
  ['N206-ts-affine-sig-twice-in-then-arm.runar.ts', 19, 'sig,', AFFINE],
  ['N207-ts-affine-sig-twice-in-else-arm.runar.ts', 21, 'sig,', AFFINE],
  // Loop body unrolled: iteration 1 consumes in one arm, iteration 2's then
  // arm (the first statement it reaches) is the second consumption.
  ['N208-ts-affine-sig-if-else-in-repeating-loop.runar.ts', 20, 'sig,', AFFINE],
  ['N209-ts-affine-sig-if-condition-and-arm.runar.ts', 21, 'sig,', AFFINE],
];

/** Still divergent on the anchor node (see header). [fixture, message fragment]. */
const ANCHOR_PENDING: Array<[string, string]> = [
  ['N220-ts-rabin-pubkey-param.runar.ts', 'verifyRabinSig public key'],
];

function expectedColumn(fixture: string, line: number, anchor: string): number {
  const text = readFileSync(join(REPO, 'conformance/negatives', fixture), 'utf8').split('\n')[line - 1] ?? '';
  const col = text.indexOf(anchor);
  if (col < 0) throw new Error(`${fixture}:${line}: anchor ${JSON.stringify(anchor)} not on that line`);
  if (text.indexOf(anchor, col + 1) >= 0) throw new Error(`${fixture}:${line}: anchor ${JSON.stringify(anchor)} not unique`);
  return col;
}

/** The `L:C` printed on the first diagnostic line carrying `message`, or null. */
function locationOf(diag: string, fixture: string, message: string): string | null {
  const esc = fixture.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const line = diag.split('\n').find((l) => l.includes(message));
  if (line === undefined) return null;
  const m = line.match(new RegExp(`${esc}:(\\d+):(\\d+):`));
  return m ? `${m[1]}:${m[2]}` : null;
}

describe('N-233: every tier anchors a diagnostic at the same node', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, line, anchor, message] of CASES) {
    it(`${fixture} -> :${line}:<column of ${JSON.stringify(anchor)}>`, () => {
      const want = `${line}:${expectedColumn(fixture, line, anchor)}`;
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print ${JSON.stringify(message)}`).toContain(message);
        got[tier.id] = locationOf(r.diag, fixture, message);
      }
      expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, want])));
    }, 900_000);
  }

  for (const [fixture, message] of ANCHOR_PENDING) {
    it(`${fixture} still diverges on the anchor node (pending; move to CASES when fixed)`, () => {
      const got = new Set<string | null>();
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print ${JSON.stringify(message)}`).toContain(message);
        got.add(locationOf(r.diag, fixture, message));
      }
      expect(got.size).toBeGreaterThan(1);
    }, 900_000);
  }
});
