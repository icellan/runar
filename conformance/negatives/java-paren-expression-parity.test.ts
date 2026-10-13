import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';
import { isCiEnv } from '../anf-interpreter/driver-gate.js';

/**
 * Seven-tier byte parity for a parenthesised identifier on `.runar.java`.
 *
 * The Zig tier's Java parser read every `(identifier)` as a cast
 * `(Type) operand`: it skipped the identifier as a type and parsed the NEXT
 * unary expression as the operand. `(((value)))` was refused with
 * `unexpected token: ')'`, and `(value) - other` compiled as `-other` — the
 * left operand silently dropped, a different locking script from the one the
 * other six tiers emit. Rúnar Java has no casts; the TS reference parses `(` as
 * a parenthesised expression only.
 *
 * Proves: for both shapes every available tier emits the TS reference's bytes,
 * in both fold modes, and those bytes equal the unparenthesised spelling's.
 * Does not prove: other surfaces, or any shape beyond these two.
 */

const HEAD = `package p;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;

import static runar.lang.Builtins.assertThat;

class P extends SmartContract {
    @Readonly Bigint limit;
    P(Bigint limit) { super(limit); this.limit = limit; }
    @Public
    void check(Bigint value, Bigint other) {
        Bigint result = `;
const TAIL = `;
        assertThat(result.gt(this.limit));
    }
}
`;

const SHAPES: Array<[string, string]> = [
  ['(value) - other', 'value - other'],
  ['(((value)))', 'value'],
];

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF_TIERS: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'java-paren-'));
});

let seq = 0;
function write(expr: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'P.runar.java');
  writeFileSync(p, HEAD + expr + TAIL);
  return p;
}

describe('.runar.java parenthesised identifier: seven-tier byte parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF_TIERS],
  ] as const) {
    for (const [paren, plain] of SHAPES) {
      it(`\`${paren}\` (${mode}): every tier emits the TS bytes of \`${plain}\``, () => {
        const ts = tiers.find((t) => t.id === 'ts');
        expect(ts, 'the TS reference tier is required').toBeDefined();
        const want = compileHex(ts!, write(plain));
        const file = write(paren);
        for (const tier of tiers) {
          expect(compileHex(tier, file), `${tier.id} on \`${paren}\``).toBe(want);
        }
      }, 300_000);
    }
  }
});
