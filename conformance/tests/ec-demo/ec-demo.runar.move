module ECDemo {
    use runar::types::{Point, ByteString};
    use runar::crypto::{ecPointX, ecPointY, ecMakePoint, ecOnCurve, ecAdd, ecMul, ecMulGen, ecNegate, ecModReduce, ecEncodeCompressed};

    resource struct ECDemo {
        pt: Point,
    }

    public fun check_x(contract: &ECDemo, expected_x: bigint) {
        assert!(ecPointX(contract.pt) == expected_x, 0);
    }

    public fun check_y(contract: &ECDemo, expected_y: bigint) {
        assert!(ecPointY(contract.pt) == expected_y, 0);
    }

    public fun check_make_point(contract: &ECDemo, x: bigint, y: bigint, expected_x: bigint, expected_y: bigint) {
        let p: Point = ecMakePoint(x, y);
        assert!(ecPointX(p) == expected_x, 0);
        assert!(ecPointY(p) == expected_y, 0);
    }

    public fun check_on_curve(contract: &ECDemo) {
        assert!(ecOnCurve(contract.pt), 0);
    }

    public fun check_add(contract: &ECDemo, other: Point, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_mul(contract: &ECDemo, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMul(contract.pt, scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_mul_gen(contract: &ECDemo, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    public fun check_negate(contract: &ECDemo, expected_neg_y: bigint) {
        let neg: Point = ecNegate(contract.pt);
        assert!(ecPointY(neg) == expected_neg_y, 0);
    }

    public fun check_negate_roundtrip(contract: &ECDemo) {
        let neg1: Point = ecNegate(contract.pt);
        let neg2: Point = ecNegate(neg1);
        assert!(ecPointX(neg2) == ecPointX(contract.pt), 0);
        assert!(ecPointY(neg2) == ecPointY(contract.pt), 0);
    }

    public fun check_mod_reduce(contract: &ECDemo, value: bigint, modulus: bigint, expected: bigint) {
        assert!(ecModReduce(value, modulus) == expected, 0);
    }

    public fun check_encode_compressed(contract: &ECDemo, expected: ByteString) {
        let compressed: ByteString = ecEncodeCompressed(contract.pt);
        assert!(compressed == expected, 0);
    }

    public fun check_mul_identity(contract: &ECDemo) {
        let result: Point = ecMul(contract.pt, 1);
        assert!(ecPointX(result) == ecPointX(contract.pt), 0);
        assert!(ecPointY(result) == ecPointY(contract.pt), 0);
    }

    public fun check_add_on_curve(contract: &ECDemo, other: Point) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecOnCurve(result), 0);
    }

    public fun check_mul_gen_on_curve(contract: &ECDemo, scalar: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecOnCurve(result), 0);
    }
}
