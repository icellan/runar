import { StatefulSmartContract, assert } from 'runar-lang';

/**
 * BoundedCounter — demonstrates property initializers.
 *
 * Properties with `= value` defaults are excluded from the constructor,
 * simplifying deployment. Only `maxCount` needs to be provided at deploy time;
 * `count` starts at 0 and `active` starts as true automatically.
 */
class BoundedCounter extends StatefulSmartContract {
  count: bigint = 0n;
  readonly maxCount: bigint;
  readonly active: boolean = true;

  constructor(maxCount: bigint) {
    super(maxCount);
    this.maxCount = maxCount;
  }

  public increment(amount: bigint) {
    assert(this.active);
    this.count = this.count + amount;
    assert(this.count <= this.maxCount);
  }

  public reset() {
    this.count = 0n;
  }
}
