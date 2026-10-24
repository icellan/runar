import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';
import { isCiEnv } from '../env.js';

/**
 * N-036 — a runtime index anywhere in a nested FixedArray access chain is
 * refused by the FixedArray expansion pass in all seven tiers, with one
 * diagnostic, instead of surviving into stack lowering.
 *
 * Measured at base on `FixedArray<FixedArray<bigint, 2>, 2>`:
 *   - `this.grid[1n][i] = v` (literal outer, runtime inner): TS/Go/Ruby/Java
 *     refused only in stack lowering ("property 'grid__1' ... no deploy-time
 *     slot"), Rust with a different message; Python and Zig ACCEPTED.
 *   - `this.grid[i][1n] = v` and `this.grid[i][j] = v`: Zig ACCEPTED.
 *   - `assert(this.grid[1n][i] == v)`: Python ACCEPTED; others refused in
 *     stack lowering (Rust in expansion).
 * docs: examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts calls runtime
 * nested indexing an intentional compile error.
 *
 * What this proves: all eight chains below get the expected verdict in every
 * tier (the six runtime ones refused, the two fully-literal controls accepted
 * with byte-identical hex), and every tier refuses the runtime ones with the
 * same "Runtime index ... on a nested FixedArray is not supported" sentence
 * and never with a stack-lowering / deploy-time-slot message.
 * What it does NOT prove: diagnostic line/column agreement, deeper (3-level)
 * nesting, stateless contracts, or non-.runar.ts surface syntaxes.
 */

const TIERS = buildSourceTiers().filter((t) => t.cmd !== null);
const TMP = mkdtempSync(join(tmpdir(), 'n036-'));

const CONTRACT = (stmt: string) => `import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

export class Grid extends StatefulSmartContract {
  grid: FixedArray<FixedArray<bigint, 2>, 2> = [[0n, 0n], [0n, 0n]];

  constructor() {
    super();
  }

  public go(i: bigint, j: bigint, v: bigint) {
    ${stmt}
    assert(true);
  }
}
`;

const CASES: [string, string, 'accept' | 'refuse'][] = [
  ['write [1n][i] (literal outer, runtime inner)', 'this.grid[1n][i] = v;', 'refuse'],
  ['write [i][1n] (runtime outer, literal inner)', 'this.grid[i][1n] = v;', 'refuse'],
  ['write [i][j]', 'this.grid[i][j] = v;', 'refuse'],
  ['read [1n][i] (literal outer, runtime inner)', 'assert(this.grid[1n][i] === v);', 'refuse'],
  ['read [i][1n] (runtime outer, literal inner)', 'assert(this.grid[i][1n] === v);', 'refuse'],
  ['read [i][j]', 'assert(this.grid[i][j] === v);', 'refuse'],
  ['write [0n][1n] (control)', 'this.grid[0n][1n] = v;', 'accept'],
  ['read [0n][1n] (control)', 'assert(this.grid[0n][1n] === v);', 'accept'],
];

const SENTENCE = /Runtime index (access|assignment) on a nested FixedArray is not supported(?! in the)/;
const INTERNAL = /stack lowering|deploy-time slot/i;

let c = 0;
function write(text: string): string {
  const dir = join(TMP, String(c++));
  mkdirSync(dir, { recursive: true });
  const p = join(dir, 'Grid.runar.ts');
  writeFileSync(p, text);
  return p;
}

describe('N-036 mixed nested FixedArray access — seven-tier parity', () => {
  it('at least two tiers are available (all seven in CI)', () => {
    expect(TIERS.length).toBeGreaterThanOrEqual(2);
    if (isCiEnv(process.env)) expect(TIERS.length).toBe(7);
  });

  for (const [name, stmt, want] of CASES) {
    const path = write(CONTRACT(stmt));
    it(`every tier ${want}s ${name}`, () => {
      const sentences = new Set<string>();
      for (const t of TIERS) {
        const j = judge(t, path);
        expect(`${t.id}: ${j.verdict === 'accepted' ? 'accept' : 'refuse'}`).toBe(`${t.id}: ${want}`);
        if (want === 'refuse') {
          const m = SENTENCE.exec(j.diag);
          expect(`${t.id}: ${m ? 'validator sentence' : j.diag.slice(0, 300)}`).toBe(`${t.id}: validator sentence`);
          expect(`${t.id}: ${INTERNAL.test(j.diag) ? 'internal message' : 'clean'}`).toBe(`${t.id}: clean`);
          sentences.add(m![0]);
        }
      }
      if (want === 'refuse') expect([...sentences]).toHaveLength(1);
      if (want === 'accept') {
        const hexes = TIERS.map((t) => compileHex(t, path));
        for (const h of hexes) expect(h).toBe(hexes[0]);
      }
    });
  }
});
