module ECPrimitives {
    use runar::types::{Point, ByteString};
    use runar::crypto::{ecPointX, ecPointY, ecOnCurve, ecNegate, ecModReduce, ecAdd, ecMul, ecMulGen, ecMakePoint, ecEncodeCompressed};

    resource struct ECPrimitives {
        pt: Point,
    }

    public fun check_x(contract: &ECPrimitives, expected_x: bigint) {
        assert!(ecPointX(contract.pt) == expected_x, 0);
    }

    public fun check_y(contract: &ECPrimitives, expected_y: bigint) {
        assert!(ecPointY(contract.pt) == expected_y, 0);
    }

    public fun check_on_curve(contract: &ECPrimitives) {
        assert!(ecOnCurve(contract.pt), 0);
    }

    public fun check_negate_y(contract: &ECPrimitives, expected_neg_y: bigint) {
        let negated: Point = ecNegate(contract.pt);
        assert!(ecPointY(negated) == expected_neg_y, 0);
    }

    public fun check_mod_reduce(contract: &ECPrimitives, value: bigint, modulus: bigint, expected: bigint) {
        assert!(ecModReduce(value, modulus) == expected, 0);
    }

    public fun check_add(contract: &ECPrimitives, other: Point, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_mul(contract: &ECPrimitives, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMul(contract.pt, scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_mul_gen(contract: &ECPrimitives, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_make_point(contract: &ECPrimitives, x: bigint, y: bigint, expected_x: bigint, expected_y: bigint) {
        let pt: Point = ecMakePoint(x, y);
        assert!(ecPointX(pt) == expected_x, 0);
        assert!(ecPointY(pt) == expected_y, 0);
    }

    public fun check_encode_compressed(contract: &ECPrimitives, expected: ByteString) {
        let compressed: ByteString = ecEncodeCompressed(contract.pt);
        assert!(compressed == expected, 0);
    }

    public fun check_mul_identity(contract: &ECPrimitives) {
        let result: Point = ecMul(contract.pt, 1);
        assert!(ecPointX(result) == ecPointX(contract.pt), 0);
        assert!(ecPointY(result) == ecPointY(contract.pt), 0);
    }

    public fun check_negate_roundtrip(contract: &ECPrimitives) {
        let neg1: Point = ecNegate(contract.pt);
        let neg2: Point = ecNegate(neg1);
        assert!(ecPointX(neg2) == ecPointX(contract.pt), 0);
        assert!(ecPointY(neg2) == ecPointY(contract.pt), 0);
    }

    public fun check_add_on_curve(contract: &ECPrimitives, other: Point) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecOnCurve(result), 0);
    }

    public fun check_mul_gen_on_curve(contract: &ECPrimitives, scalar: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecOnCurve(result), 0);
    }
}
