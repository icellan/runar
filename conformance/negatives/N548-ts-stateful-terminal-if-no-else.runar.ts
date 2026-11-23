// Same rule as N547: a terminal StatefulSmartContract method ending in an
// `if` with no else arm, so no terminal assert. Before the fix TS, Rust,
// Ruby and Java compiled it to one script, Zig to that script plus OP_1,
// Python crashed in stack lowering and only Go refused (compile results
// observed; the scripts were not executed). Every tier refuses:
//   public method 'close' must end with an assert() call (or an if/else ...)
import { StatefulSmartContract, assert } from 'runar-lang';

class Probe extends StatefulSmartContract {
  readonly h: bigint;
  count: bigint;

  constructor(h: bigint, count: bigint) {
    super(h, count);
    this.h = h;
    this.count = count;
  }

  public close(x: bigint) {
    if (x > 5n) {
      assert(x >= this.h);
    }
  }
}
