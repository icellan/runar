// N-511 (review follow-up): an UNDECLARED private helper that returns a value
// on one path and falls through on the other compiled in all seven tiers, the
// missing path evaluating to OP_0. Every tier refuses:
//   Method 'helper' returns a value on some paths but not on every path
import { SmartContract, assert } from 'runar-lang';
class Probe extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  private helper(x: bigint) { if (x > 0n) { return x; } }
  public verify(a: bigint): void {
    assert(this.helper(a) === this.target);
  }
}
