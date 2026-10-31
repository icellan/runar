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
 * Still divergent — the ANCHOR_PENDING rows below, one representative per
 * family. They need expression-level source locations that the Go, Rust,
 * Python, Ruby, Java and Zig ASTs do not carry today (N15-N17, N200-N209:
 * typecheck errors on `.runar.ts`), or a decision on the anchor because TS
 * itself is inconsistent across surfaces (N220-N228: the verifyRabinSig
 * public-key refusal is at the call on `.runar.ts` but at the method header on
 * seven other surfaces). They are pinned as divergent so that converging one
 * fails here until its row moves into CASES.
 *
 * What this proves: for N175-N179 every tier is present, refuses, and prints
 * the precedence message at `<file>:<line>:<column of the ambiguous
 * expression>`.
 * What it does NOT prove: node parity for any other diagnostic; that a tier's
 * follow-on diagnostics (Go's "unsupported Go statement") agree; anchor
 * agreement for an ambiguous edge nested under a non-ambiguous parent, where
 * Go precedence and the C ladder pick different parent nodes.
 */

const TIERS = buildSourceTiers();
const MESSAGE = 'ambiguous operator precedence in .runar.go';

/** [fixture, 1-based line, anchor text whose first character is the position]. */
const CASES: Array<[string, number, string]> = [
  ['N175-go-precedence-and-add.runar.go', 20, 'a & b + 1'],
  ['N176-go-precedence-add-shift.runar.go', 20, 'a + b << 2'],
  ['N177-go-precedence-or-add.runar.go', 20, 'a | b + d'],
  ['N178-go-precedence-and-eq.runar.go', 22, 'a & 255 == 15'],
  ['N179-go-precedence-shift-mul.runar.go', 20, 'a << b * d'],
];

/** Still divergent on the anchor node (see header). [fixture, message fragment]. */
const ANCHOR_PENDING: Array<[string, string]> = [
  ['N15-unknown-operand-type.runar.ts', "operand of '>' must be bigint"],
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

  for (const [fixture, line, anchor] of CASES) {
    it(`${fixture} -> :${line}:<column of ${JSON.stringify(anchor)}>`, () => {
      const want = `${line}:${expectedColumn(fixture, line, anchor)}`;
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        expect(r.diag, `${tier.id} must print the precedence message`).toContain(MESSAGE);
        got[tier.id] = locationOf(r.diag, fixture, MESSAGE);
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
