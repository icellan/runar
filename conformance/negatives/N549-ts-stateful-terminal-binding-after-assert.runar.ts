// Same rule as N547: a terminal StatefulSmartContract method with a binding
// after its last assert, so no terminal assert. Before the fix TS, Rust,
// Python, Ruby and Java compiled it to one script, Zig to that script plus
// OP_1, and only Go refused (compile results observed; the scripts were not
// executed). Every tier refuses:
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
    assert(x >= this.h);
    const y: bigint = x + 1n;
  }
}
