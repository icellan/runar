// N-048: a computed FixedArray index in the right operand of && was hoisted in
// front of the statement, so it was evaluated even when the left operand is
// false. spec/semantics.md 3.7 says the right operand is then not evaluated
// at all. Every tier must refuse with:
//   FixedArray index would be evaluated out of source order: ...
// Shape: effect-free computed index in the right operand of &&.
import { SmartContract, FixedArray, assert } from 'runar-lang';

class Gate extends SmartContract {
  readonly table: FixedArray<bigint, 2> = [1n, 0n];

  constructor() {
    super();
  }

  public check(k: bigint) {
    assert(k > 0n && this.table[k - 1n] === 1n);
  }
}
