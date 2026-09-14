/**
 * R-268 / R-271 (CL-GAP-020, CL-GAP-023): a runtime FixedArray read out of
 * range silently returns the last element, while the write path is described as
 * emitting `assert(false)`. Filed twice — against the TS reference and against
 * Java — as "self-documented as deliberate, but the asymmetry is undocumented
 * outside the source".
 *
 * The reviewers are right that it is undocumented, and `03b-expand-fixed-arrays.ts`
 * is blunt about it in its own comments:
 *
 *     the chain `(idx===0)?s0:((idx===1)?s1:...:sN-1)` returns s_{N-1}
 *     when idx is out of range, which is wrong.
 *
 * This test does two things the finding asks for and one it does not.
 *
 *  1. It pins the READ behaviour as measured, through all three engines. The
 *     out-of-range read is not merely unchecked — the resulting spend is
 *     ACCEPTED by the AST interpreter, by the `@bsv/sdk` ScriptVM, and by the
 *     full-consensus `Spend.validate()` leg. Nothing downstream rejects it.
 *
 *  2. It pins the same behaviour for a well past-the-end index, so a future
 *     change that clamps differently (say, to index 0) is still caught.
 *
 *  3. It records something the finding does not claim and the source comments
 *     imply otherwise: the runtime-indexed WRITE out of range does not fail in
 *     the INTERPRETER either. It silently writes nothing — measured below by
 *     checking the state is unchanged, with an in-range write as the control
 *     proving the call really executed. The `else { assert(false); }` the source
 *     describes is about the emitted Script, which this test does not exercise.
 *
 * These are pins on CURRENT behaviour, not endorsements. Making the read refuse
 * would add a bounds check to every runtime-indexed read and move script bytes,
 * so it is deferred; documenting it is what R-268 and R-271 ask for, and
 * `docs/language-reference.md` now carries the table with a "bounds-check
 * runtime indices yourself" note.
 */

import { describe, it, expect } from 'vitest';
import { runTriModalExecution, TestContract } from 'runar-testing';

const READ_SRC = `
import { SmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class OobRead extends SmartContract {
  readonly table: FixedArray<bigint, 4> = [10n, 20n, 30n, 40n];

  constructor() {
    super();
  }

  public lookup(i: bigint, expected: bigint) {
    assert((this.table[i] + 0n) === expected);
  }
}
`;

const WRITE_SRC = `
import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class OobWrite extends StatefulSmartContract {
  table: FixedArray<bigint, 4> = [0n, 0n, 0n, 0n];

  constructor() {
    super();
  }

  public put(i: bigint) {
    this.table[i] = 7n;
    assert(true);
  }
}
`;

/** `expected` is what the contract asserts the read produced. */
function readYields(i: bigint, expected: bigint) {
  return runTriModalExecution({
    source: READ_SRC,
    fileName: 'OobRead.runar.ts',
    method: 'lookup',
    args: [i, expected],
    constructorArgs: {},
  });
}

describe('R-268 / R-271: a runtime FixedArray index is not bounds-checked', () => {
  it('control: in-range reads return the element they should', () => {
    for (const [i, v] of [
      [0n, 10n],
      [3n, 40n],
    ] as [bigint, bigint][]) {
      const r = readYields(i, v);
      expect(r.interpreterAccepted, `index ${i}`).toBe(true);
      expect(r.spendAccepted, r.spendError).toBe(true);
    }
  });

  it('an out-of-range read returns the LAST element, and consensus accepts it', () => {
    // The whole point: not "it fails safely", but "it answers, wrongly, and the
    // network takes it".
    for (const i of [4n, 99n] as bigint[]) {
      const r = readYields(i, 40n);
      expect(r.interpreterAccepted, `interpreter, index ${i}`).toBe(true);
      expect(r.vmAccepted, `ScriptVM, index ${i}`).toBe(true);
      expect(r.spendAccepted, `Spend.validate(), index ${i}: ${r.spendError}`).toBe(true);
    }
  });

  it('and it really is the LAST element, not some other slot', () => {
    // Asserting `=== 40n` above would also pass if the chain clamped to index 0
    // and the test happened to ask for 10n, so pin the negative too.
    const wrong = readYields(9n, 10n);
    expect(
      wrong.interpreterAccepted,
      'an out-of-range read produced the FIRST element; the clamp changed',
    ).toBe(false);
  });

  it('an out-of-range write silently writes nothing in the interpreter', () => {
    const control = TestContract.fromSource(WRITE_SRC, {}, 'OobWrite.runar.ts');
    control.call('put', { i: 2n });
    expect(
      (control.state as { table: bigint[] }).table,
      'the in-range control did not execute, so the out-of-range case below proves nothing',
    ).toEqual([0n, 0n, 7n, 0n]);

    const oob = TestContract.fromSource(WRITE_SRC, {}, 'OobWrite.runar.ts');
    oob.call('put', { i: 9n });
    expect(
      (oob.state as { table: bigint[] }).table,
      'the interpreter refused or wrote somewhere — either way this pin is stale',
    ).toEqual([0n, 0n, 0n, 0n]);
  });
});
