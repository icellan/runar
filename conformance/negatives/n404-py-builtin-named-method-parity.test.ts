import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-404 — a `.runar.py` property or private method spelled like a builtin's
 * snake_case name behaves identically in all seven tiers.
 *
 * Follow-up to N-017 (locals). Measured at base for 16 names (the 14 whose
 * snake->camel and builtin spellings differ, plus the controls check_sig and
 * mul_div) in three shapes:
 *   - property `name: Bigint` read via `self.name`: every tier accepts;
 *   - method called bare `name(x)`: every tier refuses (a bare name is the
 *     builtin in Python scoping, and the arity/type check fails);
 *   - method called `self.name(x)`: every tier accepts, EXCEPT
 *       require_output_p2pkh (TS and Rust accepted; the other five and native
 *       .runar.ts refuse, since `this.requireOutputP2PKH` is a stateful-only
 *       intrinsic with a literal-index rule), and
 *       check_sig (Rust alone refused).
 *
 * What this proves: those 48 verdicts, and identical hex across all tiers on
 * every accepted row.
 * What it does NOT prove: stateful contracts, leading-underscore method names,
 * or diagnostic wording (only the verdict is graded).
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n404-'));

const NAMES = [
  'safe_div', 'safe_mod', 'div_mod', 'int_to_str', 'require_output_p2pkh',
  'verify_wots', 'verify_ecdsa_p256', 'verify_ecdsa_p384',
  'verify_slh_dsa_sha2_128s', 'verify_slh_dsa_sha2_128f',
  'verify_slh_dsa_sha2_192s', 'verify_slh_dsa_sha2_192f',
  'verify_slh_dsa_sha2_256s', 'verify_slh_dsa_sha2_256f',
  'check_sig', 'mul_div',
];

const HEAD = `from runar import SmartContract, Bigint, public, assert_


class Shadow(SmartContract):
    k: Bigint

    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

`;

const METHOD = (n: string, call: string) => `${HEAD}    def ${n}(self, a: Bigint) -> Bigint:
        return a + 1

    @public
    def unlock(self, x: Bigint):
        assert_(${call} == self.k)
`;

type Shape = [string, (n: string) => string, (n: string) => 'accept' | 'refuse'];
const SHAPES: Shape[] = [
  ['property', (n) => `from runar import SmartContract, Bigint, public, assert_


class Shadow(SmartContract):
    ${n}: Bigint

    def __init__(self, ${n}: Bigint):
        super().__init__(${n})
        self.${n} = ${n}

    @public
    def unlock(self, x: Bigint):
        assert_(x == self.${n})
`, () => 'accept'],
  ['bare-called method', (n) => METHOD(n, `${n}(x)`), () => 'refuse'],
  ['self-called method', (n) => METHOD(n, `self.${n}(x)`),
    (n) => (n === 'require_output_p2pkh' ? 'refuse' : 'accept')],
];

let c = 0;
function write(text: string): string {
  const dir = join(TMP, String(c++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Shadow.runar.py');
  writeFileSync(p, text);
  return p;
}

describe('N-404 builtin-spelled python property/method — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [shape, mk, expected] of SHAPES) {
    for (const name of NAMES) {
      const path = write(mk(name));
      const want = expected(name);
      it(`every tier ${want}s ${name} as a ${shape}${want === 'accept' ? ' with identical hex' : ''}`, () => {
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
  }
});
