// N-120: a FixedArray size written as a binary literal ('0b10'). The TS
// reference reads the size with parseInt(text, 10), which stops at the radix
// prefix, and refuses. Every tier must refuse with the reference diagnostic:
//   FixedArray size must be a positive integer literal, got '0b10'
// (Rust, Python, Zig, Ruby and Java used to accept it as size 2.)
import { SmartContract, assert, FixedArray } from 'runar-lang';

class FixedArraySizeRadix extends SmartContract {
  readonly a: FixedArray<bigint, 0b10> = [1n, 2n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a[0] + this.a[1]);
  }
}
