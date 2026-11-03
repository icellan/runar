import { describe, it, expect, beforeAll } from 'vitest';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex, judge } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-421 — a Move `while` whose loop variable is not declared by the statement
 * IMMEDIATELY before it is refused by every tier with the shared shape
 * sentence (docs/formats/move.md: "the declaration immediately before the
 * `while`").
 *
 * The Zig tier folded `let i = K; while (i < N) {...}` only when the
 * declaration was adjacent, but when it was not it silently kept the default
 * start of 0 and compiled the loop as if `i` began at 0 (fail-open: the
 * declared `3` was ignored). The other six tiers refused. This is the Move
 * analogue of N-008 (`.runar.zig`, `__while_no_init`).
 *
 * Proves: for three non-adjacent shapes (an unrelated `let` between the
 * declaration and the loop; an assignment between them; the statement just
 * before the loop declares a DIFFERENT variable) every available tier
 * refuses and its diagnostic carries the shared "Move `while` must be a
 * bounded counting loop" sentence; and the adjacent control compiles to
 * identical hex in every tier, so the refusals are about adjacency only.
 * Does not prove: anything about other loop shapes (bound, direction, step),
 * which have their own gates, or about the other eight surfaces.
 */

const SHAPE = 'Move `while` must be a bounded counting loop';

const move = (pre: string): string => `module L {
    use runar::types::{Int};
    struct L { expected: Int, }
    public fun verify(contract: &L, seed: Int) {
${pre}
        while (i < 5) {
            acc = acc + i;
            i = i + 1;
        };
        assert_eq!(acc, contract.expected);
    }
}
`;

const CASES: Array<[string, string]> = [
  ['unrelated let between init and loop', `        let i: Int = 3;\n        let acc: Int = seed;`],
  ['assignment between init and loop', `        let acc: Int = seed;\n        let i: Int = 3;\n        acc = acc + 1;`],
  ['statement before the loop declares a different variable', `        let i: Int = 3;\n        let acc: Int = seed;\n        let j: Int = 0;`],
];
const CONTROL = `        let acc: Int = seed;\n        let i: Int = 3;`;

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const FOLD_OFF: Tier[] = TIERS.map((t) => ({
  ...t,
  argsFor: (s: string) => [...t.argsFor(s), '--disable-constant-folding'],
}));

let dir = '';
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'n421-'));
});
let seq = 0;
function write(src: string): string {
  const sub = join(dir, String(seq++));
  mkdirSync(sub, { recursive: true });
  const p = join(sub, 'L.runar.move');
  writeFileSync(p, src);
  return p;
}

describe('N-421 Move while with a non-adjacent init: seven-tier refusal parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [mode, tiers] of [
    ['fold-on', TIERS],
    ['fold-off', FOLD_OFF],
  ] as const) {
    for (const [name, pre] of CASES) {
      it(`${name} (${mode}): every tier refuses with the shape sentence`, () => {
        const file = write(move(pre));
        const got: Record<string, string> = {};
        const want: Record<string, string> = {};
        for (const tier of tiers) {
          const r = judge(tier, file);
          got[tier.id] = r.verdict === 'rejected' && r.diag.includes(SHAPE) ? 'refused: shape' : `${r.verdict}: ${r.diag.slice(0, 160)}`;
          want[tier.id] = 'refused: shape';
        }
        expect(got).toEqual(want);
      }, 600_000);
    }

    it(`adjacent declaration (${mode}): control compiles to identical hex in every tier`, () => {
      const file = write(move(CONTROL));
      const hexes: Record<string, string> = {};
      const ref = compileHex(tiers.find((t) => t.id === 'ts')!, file);
      const want: Record<string, string> = {};
      for (const tier of tiers) {
        hexes[tier.id] = compileHex(tier, file);
        want[tier.id] = ref;
      }
      expect(hexes).toEqual(want);
    }, 600_000);
  }
});
