import { SmartContract, assert } from 'runar-lang';

/**
 * LoopShapes — the loop shape the corpus never had (R-102).
 *
 * The ANF `loop` node carries explicit `start` and `step` fields. Until this
 * example, the entire repository contained two `for` loops, both zero-start
 * and incrementing, so neither field was exercised — which is how Go's
 * constant folder came to drop `start` and `step` (N-128) and stay green.
 *
 * This contract closes the non-zero-start half of that gap and nothing more.
 * It holds exactly one loop, and that loop ascends:
 *
 *   loop 1 (i = 3n; i < 7n; i++):  3 + 4 + 5 + 6 = 18
 *
 * so `verify(seed)` asserts `seed + 18`.
 *
 * The descending half is still open: no fixture anywhere carries `step = -1`,
 * and three of the nine surfaces cannot spell a decrementing loop at all
 * (N-130), so that shape needs a fixture of its own rather than a second loop
 * bolted onto this one.
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
