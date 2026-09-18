// R-080 — output intrinsics lacked arity and signature checks, so a
// zero-argument `addRawOutput()` reached codegen and panicked instead of
// producing a located diagnostic. MUST NOT COMPILE.
import { StatefulSmartContract, assert } from 'runar-lang';

export class BadArity extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public go() {
    this.count = this.count + 1n;
    this.addRawOutput();
    assert(true);
  }
}
