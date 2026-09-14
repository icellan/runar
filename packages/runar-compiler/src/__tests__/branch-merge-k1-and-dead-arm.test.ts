/**
 * Cross-tier reference for three branch-merge defects fixed 2026-08-06.
 *
 * All three are the PALMER-1 family — "one stack carrier asked to hold N live
 * values" — at the k=1 / k=2 arities the 2026-08-05 branch-merged-locals fix
 * did not cover. All three reproduced in ALL SEVEN TIERS.
 *
 *   (1) FUND SAFETY, silent, fold-ON only. An `if` whose condition folds to a
 *       compile-time constant, whose STATICALLY DEAD arm rebinds exactly TWO
 *       locals both read after the branch, resolved every post-branch operand
 *       to the WRONG stack slot. Wrong in both directions: with s = -60267 the
 *       source REJECTS and the deployed script ACCEPTED (a covenant guard
 *       bypassed); with s = 1000 the source ACCEPTS and the deployed script
 *       REJECTED (an unspendable UTXO). Every tier emitted the same wrong
 *       script, so cross-tier agreement held perfectly while all seven were
 *       wrong together.
 *
 *   (2) A single local rebound FROM ITSELF in BOTH arms — `m0 = m0 + 1n` /
 *       `m0 = m0 - 1n` — was REJECTED at compile time with
 *       `value 't13' not found on stack`, in both fold modes, though the same
 *       shape compiles at k=2 and compiles without an `else`.
 *
 *   (3) The same k=1 merge under ANY compile-time-constant condition
 *       (`true`, `false && false`, `33n !== 38n`), fold-ON only.
 *
 * Root causes and the fixes:
 *   - (1) and (3): `optimizer/constant-fold.ts` blanked the statically-dead arm
 *     (`then: []`) while leaving the `if` node in place. An arm carries a
 *     STACK-SHAPE CONTRACT — for k>=2 merged locals both arms end with the
 *     identical `__merge$<i>` block that `lowerIf` counts to learn K. Blanking
 *     one arm made `countMergedLocalResults` see 0, so ONE stackMap slot was
 *     registered for K physical results. The folder no longer blanks arms.
 *   - (2): at k=1 04-anf-lower used to alias the local to the `if` binding
 *     instead of appending a merge block. When both arms READ and rebind the
 *     local they roll the parent slot and leave the result in place — net depth
 *     zero — so no depth-growth case in `lowerIf` fired and the `if`'s value
 *     went unregistered. That was first patched with a `branchInPlaceRebindDepth`
 *     predicate; the multi-result branch node SUBSUMES it. k=1 with an `else`
 *     now declares `results: ["m0"]` and both arms materialise it, so there is
 *     no alias, no in-place special case, and no depth arithmetic to get wrong.
 *     The k=1 hexes below moved in that change (the arms gained the two-binding
 *     copy-then-rebind block) and are re-pinned to the new seven-tier value.
 *
 * The hexes below are the SEVEN-TIER agreed output. The peer tiers pin the same
 * strings (each tier's own `branch_merge_k1_dead_arm` test), which is what
 * makes this a parity gate: a tier that lowers the fix differently fails its
 * own test.
 */

import { describe, it, expect } from 'vitest';
import { compile } from '../index.js';

/** k=2 locals rebound by a STATICALLY DEAD arm, both read after the branch. */
const DEAD_ARM_K2 = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly s: bigint;

  constructor(s: bigint) { super(s); this.s = s; }

  public m(p: bigint): void {
    let a: bigint = this.s;
    let b: bigint = -78n;
    if (false) {
      a = 1n;
      b = p;
    }
    assert(b <= a);
  }
}`;

/** One local rebound FROM ITSELF in both arms, read after the branch. */
const SELF_READ_BOTH_ARMS = `import { SmartContract, assert } from 'runar-lang';

class C extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) { super(a); this.a = a; }

  public m(p: bigint): void {
    assert(this.a > -1000000n);
    let m0: bigint = 1n;
    if (p > 0n) {
      m0 = (m0 + 1n);
    } else {
      m0 = (m0 - 1n);
    }
    assert(m0 > -1000000n);
  }
}`;

/** The same k=1 merge under a compile-time-constant condition. */
const CONST_CONDITION_K1 = SELF_READ_BOTH_ARMS
  .replace('if (p > 0n) {', 'if (true) {')
  .replace('m0 = (m0 + 1n);', 'm0 = 2n;')
  .replace('m0 = (m0 - 1n);', 'm0 = 3n;');

/** Seven-tier agreed hex, keyed `<shape>/<fold mode>`. */
export const BRANCH_MERGE_K1_GOLDEN = {
  'dead-arm-k2/fold-on':
    '00014e01ce006351547a6e7b757b7567527978557a7568527a75537a75527a7c7ba177',
  'dead-arm-k2/fold-off':
    '00014e8f006351537a6e7b757b75676e547a7568527a75527a757ca1',
  'self-read-both-arms/fold-on':
    '000340420f0340428f7b7ca069517b00a06351787c9376776751787c94767768517a750340420f0340428f7b7ca07777',
  'self-read-both-arms/fold-off':
    '000340420f8fa069517c00a06351787c9376776751787c94767768517a750340420f8fa0',
  'const-condition-k1/fold-on':
    '000340420f0340428f7b7ca0695151635276776753767768517a750340420f0340428f7b7ca0777777',
  'const-condition-k1/fold-off':
    '000340420f8fa0695151635276776753767768517a750340420f8fa077',
} as const;

const CASES: ReadonlyArray<readonly [keyof typeof BRANCH_MERGE_K1_GOLDEN, string, boolean]> = [
  ['dead-arm-k2/fold-on', DEAD_ARM_K2, false],
  ['dead-arm-k2/fold-off', DEAD_ARM_K2, true],
  ['self-read-both-arms/fold-on', SELF_READ_BOTH_ARMS, false],
  ['self-read-both-arms/fold-off', SELF_READ_BOTH_ARMS, true],
  ['const-condition-k1/fold-on', CONST_CONDITION_K1, false],
  ['const-condition-k1/fold-off', CONST_CONDITION_K1, true],
];

describe('branch merge at k=1 and statically-dead arms (2026-08-06)', () => {
  it.each(CASES)('%s compiles to the seven-tier agreed script', (key, source, disableConstantFolding) => {
    const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding });
    expect(r.success, r.diagnostics.map((d) => d.message).join('; ')).toBe(true);
    expect(r.artifact?.script).toBe(BRANCH_MERGE_K1_GOLDEN[key]);
  });

  // The k=1 self-read shape used to be rejected while its neighbours compiled.
  // A compiler that refuses a shape at one arity and accepts it at the next is
  // reporting a hole in its own merge machinery, not a language restriction —
  // which is why this was fixed rather than turned into a diagnostic.
  it('the k=2 sibling and the no-else sibling still compile', () => {
    const k2 = SELF_READ_BOTH_ARMS
      .replace('    let m0: bigint = 1n;', '    let m0: bigint = 1n;\n    let m1: bigint = 2n;')
      .replace('      m0 = (m0 + 1n);', '      m0 = (m0 + 1n);\n      m1 = (m1 + 1n);')
      .replace('      m0 = (m0 - 1n);', '      m0 = (m0 - 1n);\n      m1 = (m1 - 1n);')
      .replace(
        '    assert(m0 > -1000000n);\n  }',
        '    assert((m0 > -1000000n) && (m1 > -1000000n));\n  }',
      );
    const noElse = SELF_READ_BOTH_ARMS.replace(
      '    } else {\n      m0 = (m0 - 1n);\n    }',
      '    }',
    );
    for (const [label, source] of [['k=2', k2], ['no-else', noElse]] as const) {
      for (const disableConstantFolding of [false, true]) {
        const r = compile(source, { fileName: 'C.runar.ts', disableConstantFolding });
        expect(r.success, `${label}: ${r.diagnostics.map((d) => d.message).join('; ')}`).toBe(true);
      }
    }
  });

  // The folder must not blank a statically-dead arm at ANY arity, and must not
  // treat a constant condition differently from a runtime one.
  it('a constant condition and a runtime condition agree on every arity', () => {
    for (const cond of ['if (false) {', 'if (true) {', 'if (p > 0n) {']) {
      for (const disableConstantFolding of [false, true]) {
        const r = compile(DEAD_ARM_K2.replace('if (false) {', cond), {
          fileName: 'C.runar.ts',
          disableConstantFolding,
        });
        expect(
          r.success,
          `${cond} (fold ${disableConstantFolding ? 'OFF' : 'ON'}): ` +
            r.diagnostics.map((d) => d.message).join('; '),
        ).toBe(true);
      }
    }
  });
});
