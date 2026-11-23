// N-511: a private method that declares a non-void return type must return a
// value on every path. Before the fix a bare `return;` was refused only by an
// internal stack-lowering error ("value 't2' not found on stack"). Every tier refuses:
//   Method 'helper' declares return type 'bigint' but does not return a value
//   on every path
import { SmartContract, assert } from 'runar-lang';

class Probe extends SmartContract {
  readonly target: bigint;

  constructor(target: bigint) {
    super(target);
    this.target = target;
  }

  private helper(x: bigint): bigint {
    return;
  }

  public verify(a: bigint): void {
    assert(this.helper(a) === this.target);
  }
}
