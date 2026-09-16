// W4 / PhantomLap, second shape — the condition tests a DIFFERENT variable.
//
// N40 covers a computed left-hand side. This one is the shape that looks most
// like a typo and is the easiest to write by accident: the loop declares `i`
// and the condition tests `j`, a method parameter. `extractLoopShape` reads the
// bound from `condition.right` and the start from the init, so the trip count
// here is 3 no matter what the caller passes as `j` -- including values that
// make the source loop run zero times or forever.
//
// R-065's `validateForUpdate` does not catch it. That rule's allowed-name list
// is `{declared iterator} + {identifier the condition tests}` precisely so the
// Zig tier's unfolded `while` can advance the variable named in the condition,
// so `j` is an ACCEPTED name there. It constrains the update clause, never the
// condition.
//
// Every tier must refuse this.

import { SmartContract, assert } from 'runar-lang';

class StrayCondition extends SmartContract {
  readonly tag: bigint;

  constructor(tag: bigint) {
    super(tag);
    this.tag = tag;
  }

  public verify(j: bigint) {
    let sum: bigint = 0n;
    for (let i = 0n; j < 3n; i++) {
      sum = sum + i;
    }
    assert(sum === 3n);
  }
}
