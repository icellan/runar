// N-307: a FixedArray size written as a bigint literal ('2n'). Every tier must
// refuse it with the reference diagnostic:
//   FixedArray size must be a positive integer literal, got '2n'
// (TS, Python, Zig, Ruby and Java used to accept it as size 2; Go and Rust
// refused it with other wording.)
import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeSuffix extends SmartContract {
  readonly a: FixedArray<bigint, 2n> = [1n, 2n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[1]);
  }
}
