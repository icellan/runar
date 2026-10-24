import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-032 — a `.runar.py` contract with no `__init__` gets an auto-generated
 * constructor (docs/formats/python.md: initialized properties are excluded),
 * in all seven tiers.
 *
 * Measured at base: Go/Rust/Zig/Ruby accepted; TS (auto-generated `super`
 * call had a member_expr callee instead of an identifier), Python and Java
 * (empty-body constructor) refused with "constructor must call super() as its
 * first statement".
 *
 * What this proves: for initializer-only, mixed, plain, and stateful
 * (`Readonly[...]`) contracts without `__init__`, every tier accepts with
 * byte-identical hex; and a user-written `__init__` that omits `super()`
 * is refused by every tier.
 * What it does NOT prove: diagnostic wording (only the verdict is graded),
 * AST equality beyond the hex, or other surfaces.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n032-'));

const STATELESS = (body: string) => `from runar import SmartContract, Bigint, public, assert_


class Shape(SmartContract):
${body}
`;

const CASES: [string, string, 'accept' | 'refuse'][] = [
  ['initializer-only', STATELESS(`    a: Bigint = 5

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a)`), 'accept'],
  ['two initializers', STATELESS(`    a: Bigint = 5
    b: Bigint = 6

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a + self.b)`), 'accept'],
  ['mixed initialized and not', STATELESS(`    a: Bigint = 5
    b: Bigint

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a + self.b)`), 'accept'],
  ['plain, no initializer', STATELESS(`    a: Bigint

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a)`), 'accept'],
  ['two plain, declaration order', STATELESS(`    a: Bigint
    b: Bigint

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a - self.b)`), 'accept'],
  ['stateful initializer-only', `from runar import StatefulSmartContract, Bigint, public


class Shape(StatefulSmartContract):
    count: Bigint = 0

    @public
    def inc(self):
        self.count = self.count + 1
`, 'accept'],
  ['stateful Readonly + mutable', `from runar import StatefulSmartContract, Bigint, Readonly, public, assert_


class Shape(StatefulSmartContract):
    limit: Readonly[Bigint]
    count: Bigint = 0

    @public
    def inc(self):
        self.count = self.count + 1
        assert_(self.count < self.limit)
`, 'accept'],
  ['control: explicit __init__ without super()', STATELESS(`    a: Bigint

    def __init__(self, a: Bigint):
        self.a = a

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.a)`), 'refuse'],
];

let c = 0;
function write(text: string): string {
  const dir = join(TMP, String(c++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Shape.runar.py');
  writeFileSync(p, text);
  return p;
}

describe('N-032 .runar.py without __init__ — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, src, want] of CASES) {
    const path = write(src);
    it(`every tier ${want}s: ${name}${want === 'accept' ? ' with identical hex' : ''}`, () => {
      for (const t of TIERS) {
        const j = judge(t, path);
        expect(`${t.id}: ${j.verdict === 'accepted' ? 'accept' : 'refuse'}`).toBe(`${t.id}: ${want}`);
      }
      if (want === 'accept') {
        const hexes = TIERS.map((t) => compileHex(t, path));
        for (const h of hexes) expect(h).toBe(hexes[0]);
      }
    });
  }
});
