import { SmartContract, assert } from 'runar-lang';

class IfWithoutElse extends SmartContract {
  readonly threshold: bigint;

  constructor(threshold: bigint) {
    super(threshold);
    this.threshold = threshold;
  }

  public check(a: bigint, b: bigint): void {
    let count: bigint = 0n;
    if (a > this.threshold) { count = count + 1n; }
    if (b > this.threshold) { count = count + 1n; }
    assert(count > 0n);
  }
}
