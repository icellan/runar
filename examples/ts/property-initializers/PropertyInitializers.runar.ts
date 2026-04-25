import { StatefulSmartContract, assert } from 'runar-lang';

class PropertyInitializers extends StatefulSmartContract {
  count: bigint = 0n;
  readonly maxCount: bigint;
  readonly active: boolean = true;

  constructor(maxCount: bigint) {
    super(maxCount);
    this.maxCount = maxCount;
  }

  public increment(amount: bigint): void {
    assert(this.active);
    this.count = this.count + amount;
    assert(this.count <= this.maxCount);
  }

  public reset(): void {
    this.count = 0n;
  }
}
