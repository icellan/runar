import { SmartContract, assert, p256Add, p256Mul, p256MulGen, p256OnCurve } from 'runar-lang';
import type { ByteString } from 'runar-lang';

class P256Primitives extends SmartContract {
  readonly expectedPoint: ByteString;

  constructor(expectedPoint: ByteString) {
    super(expectedPoint);
    this.expectedPoint = expectedPoint;
  }

  public verify(k: bigint, basePoint: ByteString) {
    const result: ByteString = p256Mul(basePoint, k);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyAdd(a: ByteString, b: ByteString) {
    const result: ByteString = p256Add(a, b);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }

  public verifyMulGen(k: bigint) {
    const result: ByteString = p256MulGen(k);
    assert(p256OnCurve(result));
    assert(result == this.expectedPoint);
  }
}
