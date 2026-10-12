import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { REPO, buildSourceTiers, judge } from './tier-harness.js';

/**
 * N-078 (user decision R88a) — diagnostic columns are 0-BASED in every tier.
 *
 * A `file:line:column` diagnostic prints the 0-based character index of the
 * position on its 1-based line: the same convention as the source maps
 * (conformance/source-map/README.md) and as the TS reference's own
 * `.runar.ts` surface. Before this item the seven tiers disagreed by one
 * column, per tier AND per surface: N61 printed :10:11 in TS / Python / Zig /
 * Java and :10:10 in Go / Rust / Ruby; N81 printed :20:5 only in Rust; every
 * hand-written TS parser except `.runar.ts` was 1-based; Go's `.runar.go`
 * lexer was 1-based while its AST was 0-based; and a column-0 position
 * dropped the column entirely (`file:24: ...`) in Go, Rust, Ruby and Python.
 *
 * Every expected column below is computed from the fixture's SOURCE TEXT
 * (`lineText.indexOf(anchor)`), never copied from a compiler's output.
 *
 * What this proves:
 *   - for lexer refusals on all nine surfaces and for one validator refusal
 *     (index assignment to a ByteString property) on all nine surfaces, every
 *     available tier prints `<file>:<line>:<0-based column>:`;
 *   - a refusal AT column 0 prints `:0`, not a bare `file:line:`;
 *   - every tier is present (a missing toolchain fails, it is not skipped).
 * What it does NOT prove:
 *   - that tiers point at the same NODE for every rule (N15-N17, N175-N179,
 *     N200-N209, N220-N228 disagree on the node, not the base; N-233);
 *   - columns for diagnostics that carry no location at all. Those are the
 *     NO_LOCATION rows below, pinned so the list must shrink when fixed;
 *   - tab expansion (columns count characters; a tab is one column).
 */

const TIERS = buildSourceTiers();

/** [fixture, 1-based line, anchor text whose first character is the position]. */
const CASES: Array<[string, number, string]> = [
  // Lexer refusals, one per surface (and two on .runar.ts).
  ['N61-rb-single-quote-unterminated.runar.rb', 10, "'cafe"],
  ['N62-rb-double-quote-unterminated.runar.rb', 9, '"cafe'],
  ['N63-go-string-unterminated.runar.go', 18, '"cafe'],
  ['N64-ts-string-unterminated.runar.ts', 14, '"cafe'],
  ['N73-ts-binary-invalid-digit.runar.ts', 17, '0b102'],
  ['N52-py-bytes-unterminated-swallow.runar.py', 22, 'b"cafe'],
  ['N55-sol-string-unterminated.runar.sol', 13, '"cafe'],
  ['N56-move-string-unterminated.runar.move', 12, '"cafe'],
  ['N57-zig-string-unterminated.runar.zig', 12, '"cafe'],
  ['N58-rs-string-unterminated.runar.rs', 13, '"cafe'],
  ['N59-java-string-unterminated.runar.java', 22, '"cafe'],
  ['N68-zig-radix-shadowed-identifier.runar.zig', 23, '0B1010'],
  ['N78-rs-suffix-out-of-range.runar.rs', 15, '256u8'],
  ['N80-java-int-literal-too-large.runar.java', 26, '2147483648'],
  // Validator refusal (index assignment into a ByteString property), one
  // per surface; the position is the statement's first token.
  ['N81-ts-index-assign-bytestring-prop.runar.ts', 20, 'this.blob'],
  ['N87-sol-index-assign-bytestring-prop.runar.sol', 19, 'this.blob'],
  ['N88-move-index-assign-bytestring-prop.runar.move', 17, 'contract.blob'],
  ['N89-go-index-assign-bytestring-prop.runar.go', 19, 'c.Blob'],
  ['N90-rs-index-assign-bytestring-prop.runar.rs', 18, 'self.blob'],
  ['N91-py-index-assign-bytestring-prop.runar.py', 21, 'self.blob'],
  ['N92-zig-index-assign-bytestring-prop.runar.zig', 21, 'self.blob'],
  ['N93-rb-index-assign-bytestring-prop.runar.rb', 21, '@blob'],
  ['N94-java-index-assign-bytestring-prop.runar.java', 28, 'this.blob'],
  // Column 0: the token after the class's `end` starts the line.
  ['N213-rb-method-after-class-end.runar.rb', 24, 'def drain'],
];

/**
 * Tiers that refuse the fixture with NO `file:line` location at all. That is
 * a missing location, not a column base (Go's tree-sitter TS frontend reports
 * only a line, Rust's SWC frontend only a byte span), so it is out of this
 * item's scope. Pinned: the test asserts these tiers still print no location,
 * so fixing one fails here until its row is removed.
 */
const NO_LOCATION: Record<string, string[]> = {
  'N64-ts-string-unterminated.runar.ts': ['go', 'rust'],
  'N213-rb-method-after-class-end.runar.rb': ['rust', 'python'],
};

function expectedColumn(fixture: string, line: number, anchor: string): number {
  const text = readFileSync(join(REPO, 'conformance/negatives', fixture), 'utf8').split('\n')[line - 1] ?? '';
  const col = text.indexOf(anchor);
  if (col < 0) throw new Error(`${fixture}:${line}: anchor ${JSON.stringify(anchor)} not on that line`);
  return col;
}

/** The location a tier printed for `fixture`: `L:C`, `L` (column dropped) or null. */
function printedLocation(diag: string, fixture: string): string | null {
  const esc = fixture.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = diag.match(new RegExp(`${esc}:(\\d+)(?::(\\d+))?:`));
  if (!m) return null;
  return m[2] === undefined ? m[1]! : `${m[1]}:${m[2]}`;
}

describe('N-078: diagnostic columns are 0-based in every tier', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const [fixture, line, anchor] of CASES) {
    it(`${fixture} -> :${line}:<0-based column of ${JSON.stringify(anchor)}>`, () => {
      const want = `${line}:${expectedColumn(fixture, line, anchor)}`;
      const noLoc = NO_LOCATION[fixture] ?? [];
      const got: Record<string, string | null> = {};
      for (const tier of TIERS) {
        const r = judge(tier, join(REPO, 'conformance/negatives', fixture));
        expect(r.verdict, `${tier.id} must refuse ${fixture}`).toBe('rejected');
        got[tier.id] = printedLocation(r.diag, fixture);
      }
      const expected = Object.fromEntries(TIERS.map((t) => [t.id, noLoc.includes(t.id) ? null : want]));
      expect(got).toEqual(expected);
    }, 900_000);
  }
});
