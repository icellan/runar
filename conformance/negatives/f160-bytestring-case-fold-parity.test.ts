import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Tier, buildSourceTiers, compileHex } from './tier-harness.js';

/**
 * F-160: seven-tier fold-ON parity for ByteString `===` / `!==` on literals
 * that differ only in hex case.
 *
 * `'aa'` and `'AA'` decode to the same byte, so the script's OP_EQUAL over
 * them is true. Every tier's constant folder compared the hex SOURCE TEXT
 * instead, folded `'aa' === 'AA'` to false, and under fold-ON (the CLI
 * default) compiled `OP_0 OP_IF`, so the deployed script ran the else arm
 * while the fold-OFF script of the same source runs the then arm.
 *
 * What this proves: every available tier's CLI, fold-ON, compiles the
 * mixed-case condition to the same bytes it compiles the same-case condition
 * to (`OP_1 OP_IF` for `===`, `OP_0 OP_IF` for `!==`), and its fold-OFF
 * output is unchanged and pushes the two literals as the identical push
 * `01aa`, which is why OP_EQUAL is true on-chain.
 * packages/runar-compiler/src/__tests__/optimizer.test.ts runs the TS fold-ON
 * and fold-OFF scripts through @bsv/sdk's interpreter and shows they accept
 * and reject the same unlocking inputs.
 * What it does NOT prove: execution of each peer tier's bytes (they are
 * pinned byte-identical to the TS bytes that are executed), the non-TS
 * surfaces (the fold runs on the ANF every parser lowers to), or ByteString
 * comparisons the folders do not reach (a local bound to a literal is an
 * `@ref:` alias none of them follows).
 */

const contract = (name: string, cond: string) => `import { SmartContract, assert } from 'runar-lang';

class ${name} extends SmartContract {
  constructor() {
    super();
  }

  public unlock(x: bigint) {
    if (${cond}) {
      assert(x === 1n);
    } else {
      assert(x === 2n);
    }
  }
}
`;

// <folded bool> OP_IF ... : N-138 prunes the two literal pushes the fold
// orphans (they used to be pushed, then NIPped). Re-stamped from
// 01aa01aa51637b519c7777677b529c777768 / 01aa01aa00637b519c7777677b529c777768
// after executing old, new and fold-OFF scripts on the @bsv/sdk Spend engine
// for x in -1..4: identical accept/reject on every input (N-443).
const FOLDED_TRUE = '5163519c67529c68';
const FOLDED_FALSE = '0063519c67529c68';

const CASES: Array<{ name: string; cond: string; foldOn: string; foldOff: string }> = [
  { name: 'MixedEq', cond: "'aa' === 'AA'", foldOn: FOLDED_TRUE, foldOff: '01aa01aa8763519c67529c68' },
  { name: 'MixedNeq', cond: "'aa' !== 'AA'", foldOn: FOLDED_FALSE, foldOff: '01aa01aa879163519c67529c68' },
  // Controls: same-case literals, which every folder already got right.
  { name: 'SameEq', cond: "'aa' === 'aa'", foldOn: FOLDED_TRUE, foldOff: '01aa01aa8763519c67529c68' },
  { name: 'SameNeq', cond: "'aa' !== 'aa'", foldOn: FOLDED_FALSE, foldOff: '01aa01aa879163519c67529c68' },
];

const DIR = mkdtempSync(join(tmpdir(), 'f160-bytestring-case-fold-'));
const tiers = buildSourceTiers().filter((t) => t.cmd !== null);
const foldOff = (t: Tier): Tier => ({
  ...t,
  argsFor: (s) => [...t.argsFor(s), '--disable-constant-folding'],
});

describe('F-160: ByteString equality folds over decoded bytes in every tier', () => {
  it('the TS reference tier and at least one peer are available (else the comparison is vacuous)', () => {
    expect(tiers.find((t) => t.id === 'ts')).toBeDefined();
    expect(tiers.length).toBeGreaterThanOrEqual(2);
  });

  for (const { name, cond, foldOn, foldOff: off } of CASES) {
    const file = join(DIR, `${name}.runar.ts`);
    writeFileSync(file, contract(name, cond));
    for (const tier of tiers) {
      it(`${tier.id} fold-ON compiles \`${cond}\` to the decoded-bytes verdict`, () => {
        expect(compileHex(tier, file)).toBe(foldOn);
      }, tier.timeoutMs);
      it(`${tier.id} fold-OFF compiles \`${cond}\` to OP_EQUAL over identical pushes`, () => {
        expect(compileHex(foldOff(tier), file)).toBe(off);
      }, tier.timeoutMs);
    }
  }
});
