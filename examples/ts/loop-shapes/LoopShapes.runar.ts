import { SmartContract, assert } from 'runar-lang';

/**
 * LoopShapes — the loop shapes the corpus never had (R-102).
 *
 * Every tier implements non-zero loop starts and countdown loops; the ANF
 * `loop` node carries explicit `start` and `step` fields precisely for them.
 * Until this example, the entire repository contained two `for` loops, both
 * zero-start and incrementing, so none of that code was exercised — which is
 * how Go's constant folder came to drop `start` and `step` (N-128) and stay
 * green.
 *
 *   non-zero start:  3 + 4 + 5 + 6 = 18
 *   countdown:       5 + 4 + 3 + 2 = 14
 *
 * so `verify(seed)` asserts `seed + 32`.
 */
export class LoopShapes extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  public verify(seed: bigint) {
    let acc: bigint = seed;
    for (let i = 3n; i < 7n; i++) {
      acc = acc + i;
    }
    assert(acc === this.target);
  }
}
