import { describe, it, expect, beforeAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-154 — a .runar.go `;` that separates two statements on ONE line.
 *
 * `a := x + 1; b := a + 2` and `runar.Assert(x == c.T);` are valid Go
 * (go/parser reads the `;` exactly as it reads a newline). The Go, Rust,
 * Python and Java tiers accepted them; the TS reference refused
 * ("Unexpected token in expression: ';'"), Zig refused (ParseFailed) and
 * Ruby read the `;` as an identifier named ";". User decision R56: accept the
 * same-line separator in all seven tiers, byte-identical to the
 * newline-separated form; an EMPTY statement (the N-153 shapes) stays refused.
 *
 * The rule every tier now applies (the one Rust and Python landed in N-153):
 * a `;` separates iff the token before it is on the same line and is neither
 * `{` nor another `;`. Any other `;` is an empty statement and is refused
 * with "Unexpected token in expression: ';'".
 *
 * What this proves:
 *   - every available tier compiles each same-line `;` form (two statements
 *     on a line, a trailing `;` on the last statement, `;` inside and after
 *     if / else / for bodies, `return x;` and a bare `return;`) to the bytes
 *     the TS reference emits for the newline-separated form, in both fold
 *     modes, and the TS newline form itself still emits the pinned bytes;
 *   - every available tier still refuses the empty-statement shapes that sit
 *     next to a separator (`;;`, `; ;`, `{;`, a bare `return` followed by `;`
 *     on the next line), and every tier except Go (go/parser wording) says
 *     so with the TS diagnostic.
 * What it does NOT prove: any surface other than .runar.go, or on-chain
 * behaviour of the scripts (the claim is byte identity with the newline form,
 * whose semantics are covered elsewhere).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

const UNEXPECTED_SEMI = "Unexpected token in expression: ';'";

/** A .runar.go Disc contract with the three method bodies spliced in. */
const go = (unlock: string, check = '\treturn x', guard = '\trunar.Assert(x > 0)'): string => `package contract

import runar "github.com/icellan/runar/packages/runar-go"

type Disc struct {
\trunar.SmartContract
\tT runar.Bigint \`runar:"readonly"\`
}

func (c *Disc) Unlock(x runar.Bigint) {
${unlock}
}

func (c *Disc) check(x runar.Bigint) runar.Bigint {
${check}
}

func (c *Disc) guard(x runar.Bigint) {
${guard}
}
`;

/**
 * [case name, newline-separated form, same-line `;` form, TS hex of the
 * newline form (fold ON and OFF agree)].
 */
const ACCEPTED: Array<[string, string, string, string]> = [
  [
    '`a := x + 1; b := a + 2`',
    go('\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)'),
    go('\ta := x + 1; b := a + 2\n\trunar.Assert(b == c.T)'),
    '5393009c',
  ],
  [
    'a trailing `;` on every statement, including the last',
    go('\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)'),
    go('\ta := x + 1;\n\tb := a + 2;\n\trunar.Assert(b == c.T);'),
    '5393009c',
  ],
  [
    'three statements on one line',
    go('\ta := x + 1\n\tb := a + 2\n\trunar.Assert(b == c.T)'),
    go('\ta := x + 1; b := a + 2; runar.Assert(b == c.T)'),
    '5393009c',
  ],
  [
    '`return x;` and a bare `return;` in private methods',
    go('\ty := c.check(x)\n\tc.guard(y)\n\trunar.Assert(y == c.T)', '\trunar.Assert(x > 0)\n\treturn x', '\trunar.Assert(x > 0)\n\treturn'),
    go('\ty := c.check(x); c.guard(y)\n\trunar.Assert(y == c.T)', '\trunar.Assert(x > 0); return x;', '\trunar.Assert(x > 0)\n\treturn;'),
    '7600a0697600a069009c',
  ],
  [
    '`;` inside and after if / else arms',
    go('\ty := x\n\tif y > 1 {\n\t\ty = y - 1\n\t} else {\n\t\ty = y + 1\n\t}\n\trunar.Assert(y == c.T)'),
    go('\ty := x; if y > 1 { y = y - 1; } else { y = y + 1; }; runar.Assert(y == c.T)'),
    '51787ca06351787c9476776751787c93767768517a75009c',
  ],
  [
    '`;` inside and after a for body',
    go('\ts := x\n\tfor i := 0; i < 3; i++ {\n\t\ts += i\n\t}\n\trunar.Assert(s == c.T)'),
    go('\ts := x; for i := 0; i < 3; i++ { s += i; }; runar.Assert(s == c.T)'),
    '5393009c',
  ],
];

/** [case name, source]. Every tier refuses; all but Go say UNEXPECTED_SEMI. */
const REFUSED: Array<[string, string]> = [
  ['`stmt;;`', go('\trunar.Assert(x == c.T);;')],
  ['`stmt; ;`', go('\ta := x; ;\n\trunar.Assert(a == c.T)')],
  ['`{;` at the start of an if arm', go('\tif x == c.T {; runar.Assert(true) }\n\trunar.Assert(true)')],
  ['`a := x;;` mid-body', go('\ta := x;; b := a\n\trunar.Assert(b == c.T)')],
  ['a bare `return` with `;` on the next line', go('\ty := c.check(x)\n\tc.guard(y)\n\trunar.Assert(y == c.T)', '\treturn x', '\trunar.Assert(x > 0)\n\treturn\n\t;')],
];
const SAY_IT = ['ts', 'rust', 'python', 'zig', 'ruby', 'java'];

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n154-go-semicolon-'));
});

let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'Disc.runar.go');
  writeFileSync(p, src);
  return p;
}

/** Run a tier and return its refusal diagnostic; fail if it compiled. */
function refusal(tier: Tier, file: string): string {
  const r = spawnSync(tier.cmd!, [...tier.prefix, ...tier.argsFor(file)], {
    cwd: tier.cwd,
    encoding: 'utf-8',
    timeout: tier.timeoutMs,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw new Error(`${tier.id} could not run: ${r.error.message}`);
  if (r.status === 0) throw new Error(`${tier.id} ${file}: compiled (${r.stdout.trim().slice(-40)}), expected a refusal`);
  return `${r.stderr ?? ''}\n${r.stdout ?? ''}`;
}

describe('N-154 .runar.go same-line `;` separator — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, newline, semi, pin] of ACCEPTED) {
      const ts = tiers.find((t) => t.id === 'ts');
      if (ts) {
        it(`anchor: ts (${mode}) compiles the newline form of ${name} to the pinned bytes`, () => {
          expect(compileHex(ts, write(newline))).toBe(pin);
        });
      }
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the newline form's bytes`, () => {
          expect(compileHex(tier, write(semi))).toBe(pin);
        });
      }
    }
  }

  for (const [name, src] of REFUSED) {
    for (const tier of TIERS) {
      it(`${tier.id} refuses ${name}`, () => {
        const out = refusal(tier, write(src));
        if (SAY_IT.includes(tier.id)) expect(out).toContain(UNEXPECTED_SEMI);
      });
    }
  }
});
