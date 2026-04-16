import { SmartContract, assert, p256Add, p256Mul, p256MulGen, p256OnCurve } from 'runar-lang';
import type { P256Point } from 'runar-lang';

class P256Primitives extends SmartContract {
  readonly expectedPoint: P256Point;

  constructor(expectedPoint: P256Point) {
    super(expectedPoint);
    this.expectedPoint = expectedPoint;
  }

  public verify(k: bigint, basePoint: P256Point) {
    const result: P256Point = p256Mul(basePoint, k);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyAdd(a: P256Point, b: P256Point) {
    const result: P256Point = p256Add(a, b);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyMulGen(k: bigint) {
    const result: P256Point = p256MulGen(k);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }
}
