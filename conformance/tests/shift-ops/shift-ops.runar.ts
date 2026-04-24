import { SmartContract, assert } from 'runar-lang';

class ShiftOps extends SmartContract {
  readonly a: bigint;

  constructor(a: bigint) {
    super(a);
    this.a = a;
  }

  public testShift(): void {
    const left: bigint = this.a << 3n;
    const right: bigint = this.a >> 2n;
    assert(left >= 0n || left < 0n);
    assert(right >= 0n || right < 0n);
  }
}
