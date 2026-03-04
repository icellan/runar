import { SmartContract, assert, ecPointX, ecPointY, ecOnCurve, ecNegate, ecModReduce } from 'runar-lang';
import type { Point } from 'runar-lang';

class ECPrimitives extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  public checkX(expectedX: bigint) {
    assert(ecPointX(this.pt) === expectedX);
  }

  public checkY(expectedY: bigint) {
    assert(ecPointY(this.pt) === expectedY);
  }

  public checkOnCurve() {
    assert(ecOnCurve(this.pt));
  }

  public checkNegateY(expectedNegY: bigint) {
    const negated = ecNegate(this.pt);
    assert(ecPointY(negated) === expectedNegY);
  }

  public checkModReduce(value: bigint, modulus: bigint, expected: bigint) {
    assert(ecModReduce(value, modulus) === expected);
  }
}
