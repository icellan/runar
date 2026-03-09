// ECDemo — A stateless contract demonstrating every built-in elliptic curve
// primitive available in Runar.
//
// Runar provides 10 built-in functions for secp256k1 elliptic curve
// arithmetic. These compile into Bitcoin Script opcodes that perform real
// EC math on-chain, enabling advanced cryptographic protocols like Schnorr
// signatures, zero-knowledge proofs, and key derivation — all enforced by
// the Bitcoin network.
//
// Curve: secp256k1
//   Field prime p = 2^256 - 2^32 - 977
//   Group order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//   Generator point G is a fixed curve point; ecMulGen(k) computes k*G
//   Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte
//
// The 10 EC primitives:
//   ecPointX, ecPointY, ecMakePoint, ecOnCurve, ecAdd,
//   ecMul, ecMulGen, ecNegate, ecModReduce, ecEncodeCompressed
//
// This contract is stateless (SmartContract), so each method is an
// independent spending condition. No signature checks are performed.
module ECDemo {
    use runar::types::{Point, ByteString};
    use runar::crypto::{ecPointX, ecPointY, ecMakePoint, ecOnCurve, ecAdd, ecMul, ecMulGen, ecNegate, ecModReduce, ecEncodeCompressed};

    resource struct ECDemo {
        pt: Point,
    }

    // Extract the x-coordinate from the stored point and verify it
    // matches the expected value.
    public fun check_x(contract: &ECDemo, expected_x: bigint) {
        assert!(ecPointX(contract.pt) == expected_x, 0);
    }

    // Extract the y-coordinate from the stored point and verify it
    // matches the expected value.
    public fun check_y(contract: &ECDemo, expected_y: bigint) {
        assert!(ecPointY(contract.pt) == expected_y, 0);
    }

    // Construct a point from x and y coordinates, then verify the
    // result matches the expected coordinates.
    public fun check_make_point(contract: &ECDemo, x: bigint, y: bigint, expected_x: bigint, expected_y: bigint) {
        let p: Point = ecMakePoint(x, y);
        assert!(ecPointX(p) == expected_x, 0);
        assert!(ecPointY(p) == expected_y, 0);
    }

    // Verify the stored point lies on the secp256k1 curve.
    // Checks y^2 === x^3 + 7 (mod p).
    public fun check_on_curve(contract: &ECDemo) {
        assert!(ecOnCurve(contract.pt), 0);
    }

    // Add two curve points and verify the result.
    public fun check_add(contract: &ECDemo, other: Point, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    // Multiply the stored point by a scalar and verify the result.
    public fun check_mul(contract: &ECDemo, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMul(contract.pt, scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    // Multiply the generator point G by a scalar and verify the result.
    public fun check_mul_gen(contract: &ECDemo, scalar: bigint, expected_x: bigint, expected_y: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecPointX(result) == expected_x, 0);
        assert!(ecPointY(result) == expected_y, 0);
    }

    // Negate the stored point and verify the result's y-coordinate.
    public fun check_negate(contract: &ECDemo, expected_neg_y: bigint) {
        let neg: Point = ecNegate(contract.pt);
        assert!(ecPointY(neg) == expected_neg_y, 0);
    }

    // Verify that negating a point twice returns the original point.
    // Demonstrates the involution property: -(-P) = P.
    public fun check_negate_roundtrip(contract: &ECDemo) {
        let neg1: Point = ecNegate(contract.pt);
        let neg2: Point = ecNegate(neg1);
        assert!(ecPointX(neg2) == ecPointX(contract.pt), 0);
        assert!(ecPointY(neg2) == ecPointY(contract.pt), 0);
    }

    // Perform modular reduction and verify the result.
    public fun check_mod_reduce(contract: &ECDemo, value: bigint, modulus: bigint, expected: bigint) {
        assert!(ecModReduce(value, modulus) == expected, 0);
    }

    // Compress the stored point to 33-byte public key format and verify.
    public fun check_encode_compressed(contract: &ECDemo, expected: ByteString) {
        let compressed: ByteString = ecEncodeCompressed(contract.pt);
        assert!(compressed == expected, 0);
    }

    // Verify that scalar multiplication by 1 is the identity operation.
    // For any point P: 1 * P = P.
    public fun check_mul_identity(contract: &ECDemo) {
        let result: Point = ecMul(contract.pt, 1);
        assert!(ecPointX(result) == ecPointX(contract.pt), 0);
        assert!(ecPointY(result) == ecPointY(contract.pt), 0);
    }

    // Verify that the result of ecAdd lies on the curve.
    public fun check_add_on_curve(contract: &ECDemo, other: Point) {
        let result: Point = ecAdd(contract.pt, other);
        assert!(ecOnCurve(result), 0);
    }

    // Verify that a generator multiplication result lies on the curve.
    public fun check_mul_gen_on_curve(contract: &ECDemo, scalar: bigint) {
        let result: Point = ecMulGen(scalar);
        assert!(ecOnCurve(result), 0);
    }
}
