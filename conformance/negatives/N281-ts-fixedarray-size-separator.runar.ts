// N-307: a FixedArray size written with a numeric separator ('1_0'). Every
// tier must refuse it with the reference diagnostic:
//   FixedArray size must be a positive integer literal, got '1_0'
// (TS used to read it as 1 -- parseInt stops at '_' -- while the other tiers
// read it as 10, so the same source meant arrays of different lengths.)
import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeSeparator extends SmartContract {
  readonly a: FixedArray<bigint, 1_0> = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[9]);
  }
}
