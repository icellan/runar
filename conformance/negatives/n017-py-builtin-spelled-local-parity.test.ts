import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-017 — a `.runar.py` local, parameter or for-loop variable spelled like a
 * builtin's snake_case name (`safe_div`, `verify_wots`, ...) shadows that
 * builtin, identically in all seven tiers.
 *
 * Before the fix the TS reference and the Rust tier converted the DECLARATION
 * of such a name with the generic snake->camel rule (`safe_div` -> `safeDiv`)
 * but the REFERENCE with the builtin table (`safe_div` -> `safediv`). The two
 * never met: the use resolved to the builtin and typecheck failed with
 * "Cannot compare '<builtin>' and 'bigint'", while go/python/zig/ruby/java
 * (one converter for both sites) accepted and compiled. The 14 affected
 * spellings are exactly those where the two rules differ.
 *
 * What this proves: for each of those 14 spellings, plus controls where the
 * rules agree (check_sig, ec_add, mul_div), in a local, a parameter and a
 * for-loop variable, every available tier accepts the contract and all emit
 * the same hex.
 * What it does NOT prove: property or method names spelled like a builtin
 * (not changed by N-017), nor that shadowing a builtin is good style.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n017-'));

const SPLIT_NAMES = [
  'safe_div', 'safe_mod', 'div_mod', 'int_to_str', 'require_output_p2pkh',
  'verify_wots', 'verify_ecdsa_p256', 'verify_ecdsa_p384',
  'verify_slh_dsa_sha2_128s', 'verify_slh_dsa_sha2_128f',
  'verify_slh_dsa_sha2_192s', 'verify_slh_dsa_sha2_192f',
  'verify_slh_dsa_sha2_256s', 'verify_slh_dsa_sha2_256f',
];
const CONTROLS = ['check_sig', 'ec_add', 'mul_div'];

const HEAD = `from runar import SmartContract, Bigint, public, assert_


class Shadow(SmartContract):
    k: Bigint

    def __init__(self, k: Bigint):
        super().__init__(k)
        self.k = k

`;

const SHAPES: Array<[string, (n: string) => string]> = [
  ['local', (n) => `${HEAD}    @public
    def unlock(self, x: Bigint):
        ${n} = x + 1
        assert_(${n} == self.k)
`],
  ['param', (n) => `${HEAD}    @public
    def unlock(self, ${n}: Bigint):
        assert_(${n} == self.k)
`],
  ['loop var', (n) => `${HEAD}    @public
    def unlock(self, x: Bigint):
        total = 0
        for ${n} in range(0, 3):
            total = total + ${n}
        assert_(total == self.k + x)
`],
];

let n = 0;
function write(text: string): string {
  const dir = join(TMP, String(n++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Shadow.runar.py');
  writeFileSync(p, text);
  return p;
}

describe('N-017 builtin-spelled python local — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const name of [...SPLIT_NAMES, ...CONTROLS]) {
    for (const [shape, mk] of SHAPES) {
      const path = write(mk(name));
      it(`every tier accepts ${name} as a ${shape} with identical hex`, () => {
        for (const t of TIERS) {
          const j = judge(t, path);
          expect(`${t.id}: ${j.verdict} ${j.verdict === 'rejected' ? j.diag.slice(0, 200) : ''}`)
            .toBe(`${t.id}: accepted `);
        }
        const hexes = TIERS.map((t) => compileHex(t, path));
        for (const h of hexes) expect(h).toBe(hexes[0]);
      });
    }
  }
});
