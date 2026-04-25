import {
  SmartContract, assert,
  ecPointX, ecPointY, ecOnCurve, ecNegate, ecModReduce,
  ecAdd, ecMul, ecMulGen, ecMakePoint, ecEncodeCompressed,
} from 'runar-lang';
import type { Point } from 'runar-lang';

class ECPrimitives extends SmartContract {
  readonly pt: Point;

  constructor(pt: Point) {
    super(pt);
    this.pt = pt;
  }

  // Method 0: check x-coordinate extraction
  public checkX(expectedX: bigint) {
    assert(ecPointX(this.pt) === expectedX);
  }

  // Method 1: check y-coordinate extraction
  public checkY(expectedY: bigint) {
    assert(ecPointY(this.pt) === expectedY);
  }

  // Method 2: check point is on curve
  public checkOnCurve() {
    assert(ecOnCurve(this.pt));
  }

  // Method 3: check point negation
  public checkNegateY(expectedNegY: bigint) {
    const negated = ecNegate(this.pt);
    assert(ecPointY(negated) === expectedNegY);
  }

  // Method 4: check modular reduction
  public checkModReduce(value: bigint, modulus: bigint, expected: bigint) {
    assert(ecModReduce(value, modulus) === expected);
  }

  // Method 5: check point addition (this.pt + other)
  public checkAdd(other: Point, expectedX: bigint, expectedY: bigint) {
    const result = ecAdd(this.pt, other);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  // Method 6: check scalar multiplication (this.pt * scalar)
  public checkMul(scalar: bigint, expectedX: bigint, expectedY: bigint) {
    const result = ecMul(this.pt, scalar);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  // Method 7: check generator scalar multiplication (scalar * G)
  public checkMulGen(scalar: bigint, expectedX: bigint, expectedY: bigint) {
    const result = ecMulGen(scalar);
    assert(ecPointX(result) === expectedX);
    assert(ecPointY(result) === expectedY);
  }

  // Method 8: check make point roundtrip
  public checkMakePoint(x: bigint, y: bigint, expectedX: bigint, expectedY: bigint) {
    const pt = ecMakePoint(x, y);
    assert(ecPointX(pt) === expectedX);
    assert(ecPointY(pt) === expectedY);
  }

  // Method 9: check compressed encoding
  public checkEncodeCompressed(expected: ByteString) {
    const compressed = ecEncodeCompressed(this.pt);
    assert(compressed === expected);
  }

  // Method 10: check ecMul with scalar=1 (identity — should return same point)
  public checkMulIdentity() {
    const result = ecMul(this.pt, 1n);
    assert(ecPointX(result) === ecPointX(this.pt));
    assert(ecPointY(result) === ecPointY(this.pt));
  }

  // Method 11: check negate roundtrip (negate twice should return original)
  public checkNegateRoundtrip() {
    const neg1 = ecNegate(this.pt);
    const neg2 = ecNegate(neg1);
    assert(ecPointX(neg2) === ecPointX(this.pt));
    assert(ecPointY(neg2) === ecPointY(this.pt));
  }

  // Method 12: check ecOnCurve on a computed point (ecAdd result is on curve)
  public checkAddOnCurve(other: Point) {
    const result = ecAdd(this.pt, other);
    assert(ecOnCurve(result));
  }

  // Method 13: check ecMulGen result is on curve
  public checkMulGenOnCurve(scalar: bigint) {
    const result = ecMulGen(scalar);
    assert(ecOnCurve(result));
  }
}
