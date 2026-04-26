import { SmartContract, assert } from 'runar-lang';

class BitwiseOps extends SmartContract {
  readonly a: bigint;
  readonly b: bigint;

  constructor(a: bigint, b: bigint) {
    super(a, b);
    this.a = a;
    this.b = b;
  }

  public testShift(): void {
    const left = this.a << 2n;
    const right = this.a >> 1n;
    assert(left >= 0n || left < 0n);
    assert(right >= 0n || right < 0n);
    assert(true);
  }

  public testBitwise(): void {
    const andResult = this.a & this.b;
    const orResult = this.a | this.b;
    const xorResult = this.a ^ this.b;
    const notResult = ~this.a;
    assert(andResult >= 0n || andResult < 0n);
    assert(orResult >= 0n || orResult < 0n);
    assert(xorResult >= 0n || xorResult < 0n);
    assert(notResult >= 0n || notResult < 0n);
    assert(true);
  }
}
