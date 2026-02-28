import { SmartContract, assert } from 'tsop-lang';

class BooleanLogic extends SmartContract {
  readonly threshold: bigint;

  constructor(threshold: bigint) {
    super(threshold);
    this.threshold = threshold;
  }

  public verify(a: bigint, b: bigint, flag: boolean): void {
    const aAboveThreshold: boolean = a > this.threshold;
    const bAboveThreshold: boolean = b > this.threshold;
    const bothAbove: boolean = aAboveThreshold && bAboveThreshold;
    const eitherAbove: boolean = aAboveThreshold || bAboveThreshold;
    const notFlag: boolean = !flag;
    assert(bothAbove || (eitherAbove && notFlag));
  }
}
