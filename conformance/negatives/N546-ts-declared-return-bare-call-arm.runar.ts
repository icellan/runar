// N-511 (review follow-up): a declared helper whose else arm ends in a bare
// call expression. On .runar.ts the call's value is discarded, but the shape
// compiled in all seven tiers as if it were returned. Every tier refuses:
//   Method 'helper' declares return type 'bigint' but does not return a value
//   on every path
import { SmartContract, assert } from 'runar-lang';
class Probe extends SmartContract {
  readonly target: bigint;
  constructor(target: bigint) { super(target); this.target = target; }
  private twice(x: bigint): bigint { return x * 2n; }
  private helper(x: bigint): bigint { if (x > 0n) { return x; } else { this.twice(x); } }
  public verify(a: bigint): void {
    assert(this.helper(a) === this.target);
  }
}
