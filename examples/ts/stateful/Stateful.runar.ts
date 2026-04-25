import { StatefulSmartContract, assert } from 'runar-lang';

class Stateful extends StatefulSmartContract {
  count: bigint;
  readonly maxCount: bigint;

  constructor(count: bigint, maxCount: bigint) {
    super(count, maxCount);
    this.count = count;
    this.maxCount = maxCount;
  }

  public increment(amount: bigint): void {
    this.count = this.count + amount;
    assert(this.count <= this.maxCount);
  }

  public reset(): void {
    this.count = 0n;
  }
}
