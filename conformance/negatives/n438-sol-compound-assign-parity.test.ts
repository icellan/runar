import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';

/**
 * N-438 — which compound assignment operators the `.runar.sol` surface
 * accepts, and whether all seven tiers say the same thing about each of the ten.
 *
 * The decision recorded here mirrors N-150 (`.runar.ts`): the surface has FIVE
 * compound assignment operators, `+= -= *= /= %=`, because that is the closed
 * set in spec/grammar.md (`AssignmentOperator = '=' | '+=' | '-=' | '*=' | '/=' |
 * '%='`). `&= |= ^= <<= >>=` are not in the grammar and every tier refuses them.
 *
 * Before the fix the TypeScript tier lexed only `+=` and `-=`, so `*= /= %=`
 * were refused by TS while Go, Rust, Python, Zig, Ruby and Java accepted them.
 *
 * What this proves, per tier: on a bigint local and on a mutable bigint
 * property, `x op= y` for the five grammar operators compiles to exactly the
 * hex of `x = x op y` and all seven tiers agree on that hex; `x op= y` for the
 * other five operators is refused while the spelled-out form of the same
 * program is accepted by every tier.
 * What it does NOT prove: refusal wording (differs by tier); the for-loop update
 * clause (not a grammar compound-assignment position on this surface); other
 * surfaces; on-chain execution; fold-OFF output.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n438-'));
let n = 0;

function write(text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, 'Probe.runar.sol');
  writeFileSync(path, text);
  return path;
}

const GRAMMAR_OPS = ['+', '-', '*', '/', '%'] as const;
const NON_GRAMMAR_OPS = ['&', '|', '^', '<<', '>>'] as const;

type Shape = 'bigint local' | 'bigint property';

function program(shape: Shape, op: string, compound: boolean): string {
  if (shape === 'bigint local') {
    const stmt = compound ? `a ${op}= 3;` : `a = a ${op} 3;`;
    return `pragma runar ^0.1.0;

contract Probe is SmartContract {
    bigint immutable t;

    constructor(bigint _t) {
        t = _t;
    }

    function unlock(bigint x) public {
        bigint a = x;
        ${stmt}
        require(a == this.t);
    }
}
`;
  }
  const stmt = compound ? `this.v ${op}= x;` : `this.v = this.v ${op} x;`;
  return `pragma runar ^0.1.0;

contract Probe is StatefulSmartContract {
    bigint v;

    constructor(bigint _v) {
        v = _v;
    }

    function bump(bigint x) public {
        ${stmt}
        require(this.v > 0);
    }
}
`;
}

/** The hex every tier produces for `path`; throws if the tiers disagree. */
function sharedHex(path: string, what: string): string {
  const byTier: Record<string, string> = {};
  for (const tier of TIERS) byTier[tier.id] = compileHex(tier, path);
  const distinct = new Set(Object.values(byTier));
  expect(distinct.size, `${what}: tiers disagree on the hex: ${JSON.stringify(
    Object.fromEntries(Object.entries(byTier).map(([k, v]) => [k, `${v.length / 2}B ${v.slice(0, 24)}`])),
  )}`).toBe(1);
  return [...distinct][0]!;
}

describe('N-438: .runar.sol compound assignment — seven-tier parity on all ten operators', () => {
  it('has all seven tiers', () => {
    expect(TIERS.filter((t) => t.cmd === null).map((t) => t.id)).toEqual([]);
  });

  for (const shape of ['bigint local', 'bigint property'] as const) {
    for (const op of GRAMMAR_OPS) {
      it(`${shape}: '${op}=' compiles to the bytes of 'x = x ${op} y' in every tier`, () => {
        const spelled = sharedHex(write(program(shape, op, false)), `${shape} ${op} spelled`);
        const compound = sharedHex(write(program(shape, op, true)), `${shape} ${op}=`);
        expect(compound).toBe(spelled);
      }, 900_000);
    }
    for (const op of NON_GRAMMAR_OPS) {
      it(`${shape}: '${op}=' is refused by every tier, 'x = x ${op} y' is accepted by every tier`, () => {
        const hex = sharedHex(write(program(shape, op, false)), `${shape} ${op} spelled`);
        expect(hex.length).toBeGreaterThan(0);

        const bad = write(program(shape, op, true));
        const got: Record<string, string> = {};
        for (const tier of TIERS) got[tier.id] = judge(tier, bad).verdict;
        expect(got).toEqual(Object.fromEntries(TIERS.map((t) => [t.id, 'rejected'])));
      }, 900_000);
    }
  }
});
