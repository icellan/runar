// N-048: a computed FixedArray index inside a ternary arm was hoisted in front
// of the statement, so it was evaluated whichever arm was chosen. Every tier
// must refuse with:
//   FixedArray index would be evaluated out of source order: ...
// Shape: effect-free computed index in the consequent of ?:.
import { SmartContract, FixedArray, assert } from 'runar-lang';

class Pick extends SmartContract {
  readonly table: FixedArray<bigint, 2> = [1n, 0n];

  constructor() {
    super();
  }

  public check(c: boolean, k: bigint) {
    assert((c ? this.table[k + 1n] : 0n) === 0n);
  }
}
