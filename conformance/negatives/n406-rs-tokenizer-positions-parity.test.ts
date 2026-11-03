import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-406 — on `.runar.rs`, a diagnostic that follows a multi-line block comment
 * or a string literal containing a newline carries the TS reference's line and
 * column in every tier.
 *
 * Before the fix (base matrix: remediation-logs/N-406/matrix.txt):
 *   - after a multi-line block comment the rust, python, ruby and java
 *     tokenizers reported the column one too high: a newline inside the
 *     comment reset the column and then the loop's generic `col += 1` counted
 *     the newline as well;
 *   - after a string literal containing a newline the go, rust and ruby
 *     tokenizers did not advance the line (nor reset the column), so the
 *     diagnostic pointed back at the line the string opened on.
 *
 * Each shape puts a stray `@` (refused by every tier with TS's
 * `Unexpected character '@'`, see N-020/N-214) on the same line the comment
 * or string closes on, which is the only place the wrong count is visible:
 * the next bare newline resets the column anyway.
 *
 * What this proves:
 *   - for each shape, every available tier rejects the source and its
 *     diagnostic carries `:<line>:<col>: Unexpected character '@'` with TS's
 *     line (1-based) and column (0-based), including when the newline inside
 *     the string is backslash-escaped.
 * What it does NOT prove:
 *   - positions after other multi-line constructs, or on any surface other
 *     than `.runar.rs`;
 *   - positions of the comment or string token itself, or of diagnostics
 *     after the first one;
 *   - that these sources would otherwise compile (the string literals are not
 *     valid ByteStrings); the assertion pins the lexer's diagnostic, not a
 *     template.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n406-'));

const rs = (stmt: string) => `use runar::prelude::*;

#[runar::contract]
struct Arithmetic {
    #[readonly]
    target: Int,
}

impl Arithmetic {
    pub fn verify(&self, a: Int, b: Int) {
${stmt}
        assert!(sum == self.target);
    }
}
`;

// [name, statement lines (start on line 11), TS reference position]
const SHAPES: Array<[string, string, string]> = [
  ['a multi-line block comment', `        /* one\n           two */ let sum = a + @ b;`, ':12:32: '],
  ['a string literal containing a newline', `        let s = "ab\ncd"; let sum = a + @ b;`, ':12:19: '],
  ['a string literal containing two newlines', `        let s = "ab\ncd\nef"; let sum = a + @ b;`, ':13:19: '],
  ['a string literal containing an escaped newline', `        let s = "ab\\\ncd"; let sum = a + @ b;`, ':12:19: '],
];

let n = 0;
function write(text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Arithmetic.runar.rs');
  writeFileSync(p, text);
  return p;
}

describe('N-406 .runar.rs positions after multi-line comments and strings match the TS reference', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, stmt, at] of SHAPES) {
    const path = write(rs(stmt));
    for (const tier of TIERS) {
      it(`${tier.id} reports the '@' after ${name} at TS's ${at.trim()}`, () => {
        const j = judge(tier, path);
        expect(j.verdict).toBe('rejected');
        expect(j.diag).toContain(`${at}Unexpected character '@'`);
      });
    }
  }
});
