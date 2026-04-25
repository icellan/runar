import { SmartContract, assert } from 'runar-lang';

class BoundedLoop extends SmartContract {
  readonly expectedSum: bigint;

  constructor(expectedSum: bigint) {
    super(expectedSum);
    this.expectedSum = expectedSum;
  }

  public verify(start: bigint): void {
    let sum: bigint = 0n;
    for (let i: bigint = 0n; i < 5; i++) {
      sum = sum + start + i;
    }
    assert(sum === this.expectedSum);
  }
}
