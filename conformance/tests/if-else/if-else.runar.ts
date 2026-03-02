import { SmartContract, assert } from 'runar-lang';

class IfElse extends SmartContract {
  readonly limit: bigint;

  constructor(limit: bigint) {
    super(limit);
    this.limit = limit;
  }

  public check(value: bigint, mode: boolean): void {
    let result: bigint = 0n;
    if (mode) {
      result = value + this.limit;
    } else {
      result = value - this.limit;
    }
    assert(result > 0n);
  }
}
