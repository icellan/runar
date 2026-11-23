// A terminal StatefulSmartContract method (no state write, so no injected
// continuation assert) whose body ends in a bounded for loop. Stack lowering
// VERIFYs every assert in the loop and leaves whatever is below them, here
// the deserialized `count`, as the spend result: an honest spend with
// count == 0 failed "top stack element must be truthy" (the 474-byte script
// of TS/Rust/Python/Ruby/Java), and Zig's appended OP_1 (475 bytes) failed
// CLEANSTACK on every honest spend; both executed on @bsv/sdk Spend. Go
// refused.
// Every tier refuses, with the N-071 rule applied to the lowered ANF:
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
    for (let i = 0n; i < 2n; i++) {
      assert(x >= this.h + i);
    }
  }
}
