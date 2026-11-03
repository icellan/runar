import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-153 — a .runar.go statement that starts with `{` is refused.
 *
 * The Go-surface parser read a statement-position `{ ... }` as a brace
 * composite literal (parseGoBraceLiteral), so `{ x, c.check(x) }` — not Go at
 * all — compiled, while real Go blocks (`{ y := x ... }`) were refused for
 * unrelated reasons (`:=` inside a literal). Rúnar has no block statement on
 * the .go surface (nor on .sol / .move / .rs), and the Go and Zig tiers
 * already refused; the user decision on the N-153 escalation is to refuse it
 * in every tier with "Unexpected token in expression: '{'".
 *
 * What this proves: the TS reference refuses each statement-position `{`
 * shape with that diagnostic, and still compiles a composite literal in
 * expression position (a FixedArray property initializer).
 * What it does NOT prove: the other tiers (conformance/negatives/
 * n153-statement-shape-parity.test.ts and N191 / N192 cover them).
 */

const WANT = "Unexpected token in expression: '{'";

const go = (stmt: string): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {
\trunar.SmartContract
\tT runar.Bigint \`runar:"readonly"\`
}

func (c *Disc) Unlock(x runar.Bigint) {
\t${stmt}
\trunar.Assert(true)
}

func (c *Disc) check(x runar.Bigint) runar.Bigint {
\trunar.Assert(x == c.T)
\treturn x
}
`;

const errorsOf = (src: string): string[] =>
  compile(src, { fileName: 'Disc.runar.go', disableConstantFolding: true })
    .diagnostics.filter((d) => d.severity === 'error')
    .map((d) => d.message);

describe('N-153 .runar.go statement-position `{`', () => {
  for (const stmt of [
    '{ runar.Assert(x == c.T) }',
    '{ x, c.check(x) }',
    '{ c.check(x) }',
    '{ }',
    '{\n\t\ty := x\n\t\trunar.Assert(y == c.T)\n\t}',
    'if x == c.T {\n\t\t{ runar.Assert(true) }\n\t}',
  ]) {
    it(`refuses \`${stmt.split('\n')[0]}\``, () => {
      expect(errorsOf(go(stmt))).toContain(WANT);
    });
  }

  it('control: a composite literal in expression position still compiles', () => {
    const src = `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Arr struct {
\trunar.StatefulSmartContract
\tTable [2]runar.Int
}

func (c *Arr) init() {
\tc.Table = [2]runar.Int{0, 0}
}

func (c *Arr) Bump(i runar.Int) {
\tc.Table[i]++
\trunar.Assert(true)
}
`;
    expect(compile(src, { fileName: 'Arr.runar.go' }).diagnostics.filter((d) => d.severity === 'error')).toEqual([]);
  });
});
