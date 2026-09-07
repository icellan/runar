/**
 * A user identifier must never be clobbered by a compiler-generated ANF temp.
 *
 * `04-anf-lower.ts` names its temporaries `t0, t1, t2, …` via `freshTemp()`,
 * while `emitNamed()` binds the developer's own locals into the SAME namespace
 * without reserving them. A contract that happens to name a local `t3` gets a
 * compiler temp named `t3` written on top of it.
 *
 * This is not a size or a style problem. It silently deletes asserts:
 *
 *     const t3: bigint = z - y;
 *     const t5: bigint = y - t3;
 *     assert(t5 === this.want);
 *
 * lowered to `t5 := load_prop want` clobbering the user's `t5`, so the guard
 * became `assert(want === want)` — unconditionally true. The locking script has
 * no guard at all and is spendable by anyone with any witness.
 *
 * So the failure mode is FAIL-OPEN, not fail-closed: it is not locked funds, it
 * is an unguarded UTXO. No branch is needed to reach it, and all seven tiers
 * emitted the identical wrong script, so cross-tier parity held in the broken
 * state and no conformance golden could see it.
 *
 * The sweep below is the regression gate: it is the exact search that found the
 * fail-open cases, kept so the class cannot come back rather than just the one
 * repro that happened to be reported.
 */

import { describe, it, expect } from 'vitest';
import { runDifferentialExecution } from '../oracle/index.js';

/** Shapes that mix user locals with a live pre-existing binding. */
const SHAPES: Array<[string, string]> = [
  ['no-branch', `
    const N0: bigint = z - y;
    const N2: bigint = y - N0;
    assert(N2 === this.want);`],
  ['branch-dead-merge', `
    const N0: bigint = z - y;
    let N1: bigint = 0n;
    if (x < y) { N1 = x; } else { N1 = y; }
    const N2: bigint = y - N0;
    assert(N2 === this.want);`],
  ['branch-live-merge', `
    const N0: bigint = z - y;
    let N1: bigint = 0n;
    if (x < y) { N1 = x; } else { N1 = y; }
    const N2: bigint = y - N0 + N1;
    assert(N2 === this.want);`],
];

function contract(body: string): string {
  return `
import { SmartContract, assert } from 'runar-lang';
class Repro extends SmartContract {
  readonly want: bigint;
  constructor(want: bigint) { super(want); this.want = want; }
  public unlock(x: bigint, y: bigint, z: bigint): void {${body}
  }
}
`;
}

describe('ANF temp names must not collide with user identifiers', () => {
  it('agrees with the interpreter for every t<N> local name', () => {
    const divergences: string[] = [];

    for (let i = 0; i < 14; i++) {
      for (const [shape, template] of SHAPES) {
        const body = template
          .replace(/N0/g, `t${i}`)
          .replace(/N1/g, `t${i + 1}`)
          .replace(/N2/g, `t${i + 2}`);
        for (const want of [3n, 5n, 6n]) {
          for (const fold of [false, true]) {
            const r = runDifferentialExecution({
              source: contract(body), fileName: 'R.runar.ts', method: 'unlock',
              args: [3n, 5n, 7n], constructorArgs: { want },
              disableConstantFolding: fold,
            });
            if (!r.agrees) {
              const kind = r.vmAccepted && !r.interpreterAccepted ? 'FAIL-OPEN' : 'fail-closed';
              divergences.push(
                `${kind} ${shape} t${i} want=${want} fold=${fold} ` +
                `interp=${r.interpreterAccepted} vm=${r.vmAccepted}`);
            }
          }
        }
      }
    }

    expect(divergences.join('\n')).toBe('');
  });

  it('keeps the assert when a local shadows the temp that holds the property', () => {
    // The narrowest statement of the defect: this contract must NOT be
    // spendable with the wrong `want`. Before the fix the compiled guard was
    // `assert(want === want)` and every witness passed.
    const body = `
    const t3: bigint = z - y;
    const t5: bigint = y - t3;
    assert(t5 === this.want);`;
    const wrong = runDifferentialExecution({
      source: contract(body), fileName: 'R.runar.ts', method: 'unlock',
      args: [3n, 5n, 7n], constructorArgs: { want: 999n },
    });
    expect(wrong.interpreterAccepted).toBe(false);
    expect(wrong.vmAccepted).toBe(false);

    const right = runDifferentialExecution({
      source: contract(body), fileName: 'R.runar.ts', method: 'unlock',
      args: [3n, 5n, 7n], constructorArgs: { want: 3n },
    });
    expect(right.interpreterAccepted).toBe(true);
    expect(right.vmAccepted).toBe(true);
  });
});
