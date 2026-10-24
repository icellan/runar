import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, compileHex, type Tier } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-409 — two .runar.py accept/reject splits, seven-tier parity.
 *
 * Base matrix (remediation-logs/N-409/matrix.txt):
 *   - `a ** 2`: refused by TS, Rust and Ruby (the operator was not parsed at
 *     all there), accepted by Go, Python, Zig and Java, each lowering it to the
 *     builtin `pow(base, exp)` call. docs/formats/python.md lists
 *     `**` -> `pow()` call, so it is a documented operator and the refusing
 *     tiers were the defect.
 *   - `def f(self) -> None:`: refused by Rust only ("Expected identifier, got
 *     NoneLit" plus a follow-on "Type '_error' ..." diagnostic), accepted by the
 *     other six. `None` is Python's spelling of "returns nothing".
 *
 * Every tier now accepts both. `**` binds tighter than a unary minus on its
 * left and is right-associative, with a unary operand allowed on its right,
 * exactly as in Python; each form must compile to the same bytes as the
 * equivalent explicit `pow_(...)` call in the same tier, and to the same bytes
 * in every tier.
 *
 * What this proves:
 *   - every available tier compiles each `**` form and each `-> None` form;
 *   - the `**` forms compile to the same hex as the explicit `pow_` spelling
 *     (so precedence and associativity are those of Python), and the same hex
 *     in every tier, in both fold modes;
 *   - a `-> None` annotation on a public and on a private method does not
 *     change the compiled bytes.
 * What it does NOT prove:
 *   - `**=` (still refused or dropped per tier, not touched here);
 *   - the pow domain (`0 <= exp <= 32`) beyond what the builtin already does;
 *   - return annotations other than `None`.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));
const TMP = mkdtempSync(join(tmpdir(), 'n409-'));

let n = 0;
function write(text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Pw.runar.py');
  writeFileSync(p, text);
  return p;
}

const contract = (body: string, helper = '', annot = '') => `from runar import SmartContract, Bigint, public, assert_, pow_

class Pw(SmartContract):
    x: Bigint

    def __init__(self, x: Bigint):
        super().__init__(x)
        self.x = x
${helper}
    @public
    def check(self, a: Bigint, b: Bigint)${annot}:
${body}
`;

const POW: Array<[string, string, string]> = [
  ['a ** 2', '        assert_(a ** 2 == self.x)', '        assert_(pow_(a, 2) == self.x)'],
  ['a ** b', '        assert_(a ** b == self.x)', '        assert_(pow_(a, b) == self.x)'],
  ['-a ** 2 (the unary minus applies to the power)', '        assert_(-a ** 2 == self.x)', '        assert_(-pow_(a, 2) == self.x)'],
  ['a ** 3 ** 2 (right-associative)', '        assert_(a ** 3 ** 2 == self.x)', '        assert_(pow_(a, pow_(3, 2)) == self.x)'],
  ['a ** -b (unary operand on the right)', '        assert_(a ** -b == self.x)', '        assert_(pow_(a, -b) == self.x)'],
  ['a * b ** 2 (binds tighter than *)', '        assert_(a * b ** 2 == self.x)', '        assert_(a * pow_(b, 2) == self.x)'],
];

const PLAIN_BODY = '        assert_(a == self.x)';
const HELPER_NONE = `
    def helper(self, a: Bigint) -> None:
        assert_(a == self.x)
`;
const HELPER_PLAIN = `
    def helper(self, a: Bigint):
        assert_(a == self.x)
`;
const CALL_HELPER_BODY = '        self.helper(a)\n        assert_(a == self.x)';

describe('N-409 .py `**` and `-> None` — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [name, op, call] of POW) {
      const opPath = write(contract(op));
      const callPath = write(contract(call));
      for (const tier of tiers) {
        it(`${tier.id} (${mode}) compiles ${name} to the same hex as pow_`, () => {
          expect(compileHex(tier, opPath)).toBe(compileHex(tier, callPath));
        });
      }
      it(`every tier (${mode}) compiles ${name} to the same hex`, () => {
        const hexes = tiers.map((t) => compileHex(t, opPath));
        for (const h of hexes) expect(h).toBe(hexes[0]);
      });
    }

    const plain = write(contract(PLAIN_BODY));
    const nonePublic = write(contract(PLAIN_BODY, '', ' -> None'));
    const plainHelper = write(contract(CALL_HELPER_BODY, HELPER_PLAIN));
    const noneHelper = write(contract(CALL_HELPER_BODY, HELPER_NONE));
    for (const tier of tiers) {
      it(`${tier.id} (${mode}) compiles a public \`-> None\` method to the unannotated hex`, () => {
        expect(compileHex(tier, nonePublic)).toBe(compileHex(tier, plain));
      });
      it(`${tier.id} (${mode}) compiles a private \`-> None\` method to the unannotated hex`, () => {
        expect(compileHex(tier, noneHelper)).toBe(compileHex(tier, plainHelper));
      });
    }
  }
});
