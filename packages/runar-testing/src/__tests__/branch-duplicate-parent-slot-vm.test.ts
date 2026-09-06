import { describe, it, expect } from 'vitest';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

/**
 * NEW-018 — a conditional whose CONDITION is itself a conditional miscompiled
 * over loop-carried locals, and deployed to a permanently unspendable UTXO.
 *
 *     let acc: bigint = p;
 *     let wacc: bigint = 0n;
 *     for (let k = 1n; k > 0n; k--) {
 *       for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; wacc = wacc + acc; }
 *     }
 *     let br0: bigint = 0n;
 *     const sib0: bigint = p;
 *     if (p === 0n) { br0 = p; }
 *     assert((p >= 0n ? acc >= 0n : false) ? (br0 < sib0) : false);
 *
 * With `p = 1n` the source ACCEPTS and `TestContract` accepts; `ScriptVM` and
 * `@bsv/sdk`'s `Spend` reject the spend with "The top stack element must be
 * truthy after script evaluation".
 *
 * ROOT CAUSE
 * ----------
 * `lowerIf` reconciles the two arms by NAME SET. A parent stack legitimately
 * holds the same name in more than one slot — a loop rebinding a local leaves
 * one slot per unrolled iteration, all named `acc`, of which only the
 * shallowest is ever read. When an arm ROLLs that live slot away, the name is
 * STILL in the arm's name set because the dead residue beneath it carries the
 * same name, so the reconcile saw nothing consumed and emitted no matching
 * drop in the sibling.
 *
 * The depth-balance phase then compensated with an anonymous pad. A pad
 * restores the COUNT but not the POSITION: the arm that lost a slot from the
 * middle of the region got a placeholder next to its result while the sibling
 * still held the real value in the original slot. The arms left positionally
 * DIFFERENT stacks, the parent adopted one of them, and every slot the other
 * arm held below the result was off by one. The measured layouts were
 * `[t · br0 sib0 …]` against `[t br0 sib0 acc …]`.
 *
 * The fix counts occurrences instead of testing set membership, in both the
 * arm-vs-arm reconcile and the post-OP_ENDIF parent reconcile. The sibling
 * then drops its matching slot, both arms end at the same depth with the same
 * layout, and no pad is needed at all. Byte-neutral for any parent stack with
 * no duplicated name.
 *
 * WHY IT MATTERS BEYOND THE TERNARY
 * ---------------------------------
 * `a && b && c` is LEFT-associative, so the `&&` short-circuit desugar
 * (`a && b` => `a ? b : false`) makes the outer conditional's condition a
 * conditional — exactly this shape. This defect is what blocked that fix.
 */

const FILE = 'E.runar.ts';

function contract(body: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

export class E extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) { super(k); this.k = k; }
  public run1(p: bigint): void {
${body}
  }
}
`;
}

/**
 * Two loop-carried locals through nested loops, plus a plain `if` that rebinds
 * a local. `acc` ends up named by TWO parent slots (the pre-loop binding and
 * the unrolled iteration's rebinding), which is what the name-set reconcile
 * could not see. `p = 1n` => acc = 2, wacc = 2, br0 = 0, sib0 = 1.
 */
const PRELUDE = `    let acc: bigint = 0n + p;
    let wacc: bigint = 0n;
    for (let k = 1n; k > 0n; k--) {
      for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; wacc = wacc + acc; }
    }
    let br0: bigint = 0n + 0n;
    const sib0: bigint = p + 0n;
    if (p === 0n) { br0 = 0n + p; }
`;

interface Case {
  readonly label: string;
  readonly source: string;
  /** `p` => what the SOURCE says, and therefore what both engines must say. */
  readonly expect: ReadonlyArray<readonly [bigint, boolean]>;
}

const CASES: Case[] = [
  {
    label: 'the CONDITION of a ternary is a ternary (minimal)',
    source: contract(PRELUDE + '    assert((p >= 0n ? acc >= 0n : false) ? (br0 < sib0) : false);'),
    // p=1: acc=2 >= 0 so the condition is true; br0=0 < sib0=1 -> true.
    // p=-1: p >= 0 is false so the condition is false -> false.
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'two levels of ternary in the CONDITION',
    source: contract(
      PRELUDE +
        '    assert((p >= 0n ? (acc >= 0n ? (wacc !== p) : false) : false) ? (br0 < sib0) : false);',
    ),
    // p=1: acc=2, wacc=2, 2 !== 1 -> condition true; 0 < 1 -> true.
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'the same shape reading the loop local in the outer arm',
    source: contract(PRELUDE + '    assert((p >= 0n ? br0 < sib0 : false) ? (acc >= 0n) : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'a ternary condition that must evaluate FALSE',
    source: contract(PRELUDE + '    assert(!((p >= 0n ? acc < 0n : false) ? (br0 < sib0) : true));'),
    // p=1: acc=2 so `acc < 0n` is false -> condition false -> alternate `true`
    // -> the assert negates it -> REJECT. p=-1: condition false -> true -> REJECT.
    expect: [[1n, false], [-1n, false]],
  },

  // --- controls: green before the fix, and must stay green -----------------
  {
    label: 'CONTROL the eager `&&` chain over the same locals',
    source: contract(
      PRELUDE + '    assert(p >= 0n && (acc >= 0n && wacc !== p) && br0 < sib0);',
    ),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL a ternary nested in an ARM, not in the condition',
    source: contract(
      PRELUDE +
        '    assert(p >= 0n ? ((acc >= 0n ? (wacc !== p) : false) ? (br0 < sib0) : false) : false);',
    ),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL two levels of ternary, both in arms',
    source: contract(PRELUDE + '    assert(p >= 0n ? (acc >= 0n ? br0 < sib0 : false) : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL plain reads of every local after the loop',
    source: contract(
      PRELUDE +
        '    assert(acc >= 0n);\n    assert(wacc >= 0n);\n    assert(br0 <= sib0);',
    ),
    // p=-1: acc = -2 -> REJECT.
    expect: [[1n, true], [-1n, false]],
  },
];

describe('NEW-018 — a ternary whose condition is a ternary must stay spendable', () => {
  for (const c of CASES) {
    for (const [arg, accepts] of c.expect) {
      it(`${c.label}: p=${arg} => ${accepts ? 'ACCEPT' : 'REJECT'} on both engines`, () => {
        const r = runStatelessSigned({
          source: c.source,
          fileName: FILE,
          method: 'run1',
          args: [arg],
          constructorArgs: { k: 1n },
        });
        expect(r.reachedEngine, `never reached Spend: ${r.vmError ?? ''}`).toBe(true);
        expect(
          r.vmAccepted,
          `the real engine disagreed with the source: ${r.vmError ?? '(accepted)'}`,
        ).toBe(accepts);
        expect(
          r.interpreterAccepted,
          `TestContract disagreed with the real engine: ${r.interpreterError ?? '(accepted)'}`,
        ).toBe(accepts);
      });
    }
  }
});
