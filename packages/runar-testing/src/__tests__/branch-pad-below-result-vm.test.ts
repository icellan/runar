import { describe, it, expect } from 'vitest';
import { runStatelessSigned } from '../oracle/real-crypto-execution.js';

/**
 * NEW-017 — a nested conditional over loop-carried locals lost its result to
 * the depth-balance PAD, and deployed to a permanently unspendable UTXO.
 *
 *     let acc: bigint = p;
 *     let wacc: bigint = 0n;
 *     for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; wacc = wacc + acc; }
 *     assert(p >= 0n ? (acc >= 0n ? true : false) : false);
 *
 * With `p = 1n` the source ACCEPTS and `TestContract` accepts. The deployed
 * script ends
 *
 *     … OP_IF OP_TRUE OP_ELSE OP_FALSE OP_ENDIF OP_0 OP_NIP OP_NIP OP_NIP OP_NIP
 *
 * and `@bsv/sdk`'s `Spend` rejects the spend with "The top stack element must
 * be truthy after script evaluation" — the trailing `OP_0` is the pad, sitting
 * where the arm's `OP_TRUE` should be.
 *
 * ROOT CAUSE
 * ----------
 * `lowerIf` balances the two arms in three phases. Phase 1 drops slots one arm
 * consumed from the other, but it only looks at NAMED slots (`preIfNames`), so
 * an ANONYMOUS inherited slot — the residue an unrolled loop leaves behind —
 * is invisible to it. Phase 3 then sees a raw depth difference and compensates
 * by pushing an empty placeholder ON TOP. That is correct for the
 * if-WITHOUT-else shapes phase 3 was written for, where the padded arm holds
 * no result of its own; for a VALUE-producing conditional the push lands on
 * top of the arm's result and becomes the result.
 *
 * The fix swaps the pad UNDER the top slot for the value-producing shape (both
 * arms carry bindings, node declares no results), so the arm's result stays
 * where every consumer already assumes it is. Byte-neutral everywhere else.
 *
 * WHY THE SHAPE IS SO SPECIFIC
 * ----------------------------
 * It needs (a) a nested conditional — the inner one is what consumes the
 * anonymous slot, (b) TWO loop-carried locals — with one, the arm's depth
 * happens to land right, and (c) the inner condition reading the DEEPER of the
 * two. Each of those is pinned below as a control that must stay green, so a
 * fix that simply stops padding cannot pass.
 *
 * `&&` / `||` desugar to this node, so `a && (b && c)` over loop-carried
 * locals reaches it from ordinary source.
 */

const FILE = 'E.runar.ts';

function contract(body: string): string {
  return `import { SmartContract, assert } from 'runar-lang';

export class E extends SmartContract {
  readonly k: bigint;
  constructor(k: bigint) { super(k); this.k = k; }
  public run1(p: bigint): void {
${body}
    assert(this.k > 0n);
  }
}
`;
}

/** Two loop-carried locals, single loop. */
const LOOP2 = `    let acc: bigint = p;
    let wacc: bigint = 0n;
    for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; wacc = wacc + acc; }
`;

/** Two loop-carried locals, nested loops — the shape the exec fuzzer found. */
const NESTED_LOOP2 = `    let acc: bigint = p;
    let wacc: bigint = 0n;
    for (let k = 1n; k > 0n; k--) {
      for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; wacc = wacc + acc; }
    }
`;

/** One loop-carried local. */
const LOOP1 = `    let acc: bigint = p;
    for (let k2 = 0n; k2 < 1n; k2++) { acc = acc + p; }
`;

interface Case {
  readonly label: string;
  readonly source: string;
  /** `p` => what the SOURCE says, and therefore what both engines must say. */
  readonly expect: ReadonlyArray<readonly [bigint, boolean]>;
}

const CASES: Case[] = [
  {
    label: 'nested ternary reads the deeper of two loop-carried locals',
    // acc = 2p, so `acc >= 0n` is true for p >= 0 and false for p < 0.
    source: contract(LOOP2 + '    assert(p >= 0n ? (acc >= 0n ? true : false) : false);'),
    expect: [[1n, true], [7n, true], [-1n, false]],
  },
  {
    label: 'same, through nested loops (exec-fuzzer counterexample)',
    source: contract(NESTED_LOOP2 + '    assert(p >= 0n ? (acc >= 0n ? true : false) : false);'),
    expect: [[1n, true], [7n, true], [-1n, false]],
  },
  {
    label: 'nested ternary whose inner arm reads the loop local',
    source: contract(LOOP2 + '    assert(p >= 0n ? (p > 100n ? false : acc >= 0n) : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'the `&&` chain that desugars to it',
    source: contract(LOOP2 + '    assert(p >= 0n && (acc >= 0n && wacc !== p));'),
    // p=1: acc=2, wacc=2, 2 !== 1 -> true. p=-1: p >= 0 false -> false.
    expect: [[1n, true], [-1n, false]],
  },

  // --- controls: green before the fix, and must stay green ----------------
  {
    label: 'CONTROL flat ternary over the same loop locals',
    source: contract(LOOP2 + '    assert(acc >= 0n ? true : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL nested ternary with ONE loop-carried local',
    source: contract(LOOP1 + '    assert(p >= 0n ? (acc >= 0n ? true : false) : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL nested ternary reading the SHALLOWER loop local',
    source: contract(LOOP2 + '    assert(p >= 0n ? (wacc >= 0n ? true : false) : false);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL nested ternary that reads no loop local',
    source: contract(LOOP2 + '    assert(p >= 0n ? (p >= 0n ? true : false) : false);\n    assert(acc >= 0n);'),
    expect: [[1n, true], [-1n, false]],
  },
  {
    label: 'CONTROL plain reads of both loop locals',
    source: contract(LOOP2 + '    assert(acc >= 0n);\n    assert(wacc >= 0n);'),
    expect: [[1n, true], [-1n, false]],
  },
];

describe('NEW-017 — the branch depth pad must not displace the arm result', () => {
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
