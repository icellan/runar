// N-121 (user decision R85): `this.a?.[0]` is optional chaining on an index
// access. Every tier must refuse it with the shared diagnostic, located at
// the `?` of `?.`.
import { SmartContract, assert, FixedArray } from 'runar-lang';

class Probe extends SmartContract {
  readonly a: FixedArray<bigint, 2> = [1n, 2n];

  constructor() {
    super();
  }

  public unlock(x: bigint) {
    assert(x === this.a?.[0]);
  }
}
