import { SmartContract, assert, p384Add, p384Mul, p384MulGen, p384OnCurve } from 'runar-lang';
import type { P384Point } from 'runar-lang';

class P384Primitives extends SmartContract {
  readonly expectedPoint: P384Point;

  constructor(expectedPoint: P384Point) {
    super(expectedPoint);
    this.expectedPoint = expectedPoint;
  }

  public verify(k: bigint, basePoint: P384Point) {
    const result: P384Point = p384Mul(basePoint, k);
    assert(p384OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyAdd(a: P384Point, b: P384Point) {
    const result: P384Point = p384Add(a, b);
    assert(p384OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyMulGen(k: bigint) {
    const result: P384Point = p384MulGen(k);
    assert(p384OnCurve(result));
    assert(result == this.expectedPoint);
  }
}
