import { InductiveSmartContract, assert } from 'runar-lang';

class Inductive extends InductiveSmartContract {
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
