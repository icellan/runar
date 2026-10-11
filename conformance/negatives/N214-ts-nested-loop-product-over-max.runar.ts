// N-202: each loop alone is within MAX_LOOP_COUNT (10,000), but the inner one
// is nested inside the outer, so the unrolled work is 101 x 100 = 10,100
// iterations. Every tier must refuse it from source with the product
// diagnostic the --ir loaders already give (F-283 / I58):
//   ... nested inside an enclosing loop of total count 101, producing 10100
//   total iterations, exceeding maximum 10000
// Before N-202 the source path checked each loop on its own, so this compiled
// from source while its emitted IR was refused on --ir replay, and a 9000 x
// 9000 nest hung the compiler with no diagnostic.
import { SmartContract, assert } from 'runar-lang';

class NestedLoopProductOverMax extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public go(x: bigint) {
    let s: bigint = 0n;
    for (let i = 0n; i < 101n; i++) {
      for (let j = 0n; j < 100n; j++) {
        s = s + x;
      }
    }
    assert(s > this.a);
  }
}
