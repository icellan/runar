import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/**
 * N-154 — a .runar.go `;` that separates statements on one line is accepted
 * (user decision R56: it is valid Go), byte-identical to the newline form.
 * An empty statement stays refused (N-153).
 *
 * Pre-fix the TS reference refused `a := x + 1; b := a + 2` and
 * `runar.Assert(x == c.T);` with "Unexpected token in expression: ';'", while
 * the Go, Rust, Python and Java tiers compiled them.
 *
 * What this proves: the TS reference compiles each same-line `;` form to the
 * same hex as its newline form, and still refuses `;;`, `; ;`, `{;` and a `;`
 * on the line after a bare `return` with the shared diagnostic.
 * What it does NOT prove: the other tiers
 * (conformance/negatives/n154-go-semicolon-separator-parity.test.ts and N271).
 */

const WANT = "Unexpected token in expression: ';'";

const go = (unlock: string, guard = '\trunar.Assert(x > 0)'): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {
\trunar.SmartContract
\tT runar.Bigint \`runar:"readonly"\`
}

func (c *Disc) Unlock(x runar.Bigint) {
${unlock}
}

func (c *Disc) guard(x runar.Bigint) {
${guard}
}
`;

const run = (src: string) => compile(src, { fileName: 'Disc.runar.go', disableConstantFolding: true });
const errorsOf = (src: string): string[] =>
  run(src).diagnostics.filter((d) => d.severity === 'error').map((d) => d.message);
const hexOf = (src: string): string | undefined => {
  expect(errorsOf(src)).toEqual([]);
  return run(src).scriptHex;
};

describe('N-154 .runar.go same-line `;` separator', () => {
  for (const [name, newline, semi] of [
    ['two statements on one line', go('\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)'), go('\ta := x + 1; b := a + 2\n\trunar.Assert(b == c.T)')],
    ['a trailing `;` on the last statement', go('\trunar.Assert(x == c.T)'), go('\trunar.Assert(x == c.T);')],
    ['`;` in and after if / else arms', go('\ty := x\n\tif y > 1 {\n\t\ty = y - 1\n\t} else {\n\t\ty = y + 1\n\t}\n\trunar.Assert(y == c.T)'), go('\ty := x; if y > 1 { y = y - 1; } else { y = y + 1; }; runar.Assert(y == c.T)')],
    ['`;` in and after a for body', go('\ts := x\n\tfor i := 0; i < 3; i++ {\n\t\ts += i\n\t}\n\trunar.Assert(s == c.T)'), go('\ts := x; for i := 0; i < 3; i++ { s += i; }; runar.Assert(s == c.T)')],
    ['a bare `return;`', go('\tc.guard(x)\n\trunar.Assert(x == c.T)', '\trunar.Assert(x > 0)\n\treturn'), go('\tc.guard(x); runar.Assert(x == c.T)', '\trunar.Assert(x > 0); return;')],
  ] as const) {
    it(`compiles ${name} to the newline form's bytes`, () => {
      const want = hexOf(newline);
      expect(want).toBeTruthy();
      expect(hexOf(semi)).toBe(want);
    });
  }

  for (const [name, src] of [
    ['`stmt;;`', go('\trunar.Assert(x == c.T);;')],
    ['`stmt; ;`', go('\ta := x; ;\n\trunar.Assert(a == c.T)')],
    ['`{;`', go('\tif x == c.T {; runar.Assert(true) }\n\trunar.Assert(true)')],
    ['a `;` on the line after a bare `return`', go('\tc.guard(x)\n\trunar.Assert(x == c.T)', '\trunar.Assert(x > 0)\n\treturn\n\t;')],
  ] as const) {
    it(`still refuses ${name}`, () => {
      expect(errorsOf(src)).toContain(WANT);
    });
  }
});
