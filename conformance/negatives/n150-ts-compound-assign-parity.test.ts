import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildSourceTiers, judge, compileHex } from './tier-harness.js';

/**
 * N-150 — which compound assignment operators the `.runar.ts` surface accepts,
 * and whether all seven tiers say the same thing about each of the ten.
 *
 * The decision recorded here: the `.runar.ts` surface has FIVE compound
 * assignment operators, `+= -= *= /= %=`, because that is the closed set in
 * spec/grammar.md (`AssignmentOperator = '=' | '+=' | '-=' | '*=' | '/=' | '%='`
 * and the "Compound assignment desugaring" note). `&= |= ^= <<= >>=` are not in
 * the grammar and every tier refuses them. The bitwise and shift OPERATORS
 * (`& | ^ << >>`) are fully supported; only their compound spelling is not, and
 * `a = a << 3n` is the way to write it.
 *
 * Measured before this test was written (all seven tiers, default flags, a
 * bigint local, a mutable bigint property of a StatefulSmartContract, and, for
 * `&= |= ^=`, a ByteString local): the five grammar operators compile in every
 * tier to the same bytes as the spelled-out `x = x op y`; the other five are
 * refused in every tier. The seven tiers already agreed, so this test is a
 * regression gate and was green at HEAD. It is not a red-to-green test.
 *
 * What this proves, per tier and per shape:
 *   - `x op= y` for the five grammar operators compiles to exactly the hex of
 *     `x = x op y`, and all seven tiers agree on that hex;
 *   - `x op= y` for the other five operators is refused, while the spelled-out
 *     form of the SAME program is accepted by every tier, so the refusal is
 *     attributable to the compound spelling alone.
 * What it does NOT prove:
 *   - anything about the wording of the refusal (the tiers differ: TS/Go name
 *     the operator, Rust names it as an unsupported compound operator, Python,
 *     Ruby, Zig and Java report an unexpected `=` token);
 *   - the compound forms on other surfaces. `.runar.java` accepts all ten in
 *     every tier and `.runar.sol` accepts `*= /= %=` in six tiers but not TS;
 *     both are separate surfaces with their own items;
 *   - on-chain execution of the bytes, or fold-OFF output.
 */

const TIERS = buildSourceTiers();
const TMP = mkdtempSync(join(tmpdir(), 'n150-'));
let n = 0;

function write(text: string): string {
  const dir = mkdtempSync(join(TMP, `c${n++}-`));
  const path = join(dir, 'Probe.runar.ts');
  writeFileSync(path, text);
  return path;
}

const GRAMMAR_OPS = ['+', '-', '*', '/', '%'] as const;
const NON_GRAMMAR_OPS = ['&', '|', '^', '<<', '>>'] as const;

type Shape = 'bigint local' | 'bigint property' | 'ByteString local';

function program(shape: Shape, op: string, compound: boolean): string {
  if (shape === 'bigint local') {
    const stmt = compound ? `a ${op}= 3n;` : `a = a ${op} 3n;`;
    return `import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: bigint;

  constructor(t: bigint) {
    super(t);
    this.t = t;
  }

  public unlock(x: bigint) {
    let a: bigint = x;
    ${stmt}
    assert(a === this.t);
  }
}
`;
  }
  if (shape === 'bigint property') {
    const stmt = compound ? `this.v ${op}= x;` : `this.v = this.v ${op} x;`;
    return `import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  v: bigint;

  constructor(v: bigint) {
    super(v);
    this.v = v;
  }

  public bump(x: bigint) {
    ${stmt}
    assert(this.v > 0n);
  }
}
`;
  }
  const stmt = compound ? `a ${op}= x;` : `a = a ${op} x;`;
  return `import { SmartContract, assert, ByteString } from 'runar-lang';

class Probe extends SmartContract {
  readonly t: ByteString;

  constructor(t: ByteString) {
    super(t);
    this.t = t;
  }

  public unlock(x: ByteString) {
    let a: ByteString = x;
    ${stmt}
    assert(a === this.t);
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

describe('N-150: .runar.ts compound assignment — seven-tier parity on all ten operators', () => {
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
  }

  const refusedShapes: Array<[Shape, readonly string[]]> = [
    ['bigint local', NON_GRAMMAR_OPS],
    ['bigint property', NON_GRAMMAR_OPS],
    ['ByteString local', ['&', '|', '^']],
  ];
  for (const [shape, ops] of refusedShapes) {
    for (const op of ops) {
      it(`${shape}: '${op}=' is refused by every tier, 'x = x ${op} y' is accepted by every tier`, () => {
        // The control must be a real, accepted program in all seven tiers.
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
