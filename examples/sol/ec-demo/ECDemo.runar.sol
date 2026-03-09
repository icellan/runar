pragma runar ^0.1.0;

/// @title ECDemo
/// @notice A stateless contract demonstrating every built-in elliptic curve
/// primitive available in Runar.
/// @dev Runar provides 10 built-in functions for secp256k1 elliptic curve
/// arithmetic. These compile into Bitcoin Script opcodes that perform real
/// EC math on-chain, enabling advanced cryptographic protocols like Schnorr
/// signatures, zero-knowledge proofs, and key derivation — all enforced by
/// the Bitcoin network.
///
/// Curve: secp256k1
///   Field prime p = 2^256 - 2^32 - 977
///   Group order n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
///   Generator point G is a fixed curve point; ecMulGen(k) computes k*G
///   Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte
///
/// The 10 EC primitives:
///   ecPointX, ecPointY, ecMakePoint, ecOnCurve, ecAdd,
///   ecMul, ecMulGen, ecNegate, ecModReduce, ecEncodeCompressed
///
/// This contract is stateless (SmartContract), so each method is an
/// independent spending condition. No signature checks are performed.
contract ECDemo is SmartContract {
    Point immutable pt;

    constructor(Point _pt) {
        pt = _pt;
    }

    /// @notice Extract the x-coordinate from the stored point and verify it
    /// matches the expected value.
    /// @param expectedX The expected x-coordinate
    function checkX(bigint expectedX) public {
        require(ecPointX(this.pt) == expectedX);
    }

    /// @notice Extract the y-coordinate from the stored point and verify it
    /// matches the expected value.
    /// @param expectedY The expected y-coordinate
    function checkY(bigint expectedY) public {
        require(ecPointY(this.pt) == expectedY);
    }

    /// @notice Construct a point from x and y coordinates, then verify the
    /// result matches the expected coordinates.
    /// @param x The x-coordinate
    /// @param y The y-coordinate
    /// @param expectedX The expected x-coordinate of the constructed point
    /// @param expectedY The expected y-coordinate of the constructed point
    function checkMakePoint(bigint x, bigint y, bigint expectedX, bigint expectedY) public {
        Point p = ecMakePoint(x, y);
        require(ecPointX(p) == expectedX);
        require(ecPointY(p) == expectedY);
    }

    /// @notice Verify the stored point lies on the secp256k1 curve.
    /// @dev Checks y^2 === x^3 + 7 (mod p).
    function checkOnCurve() public {
        require(ecOnCurve(this.pt));
    }

    /// @notice Add two curve points and verify the result.
    /// @param other The second point to add
    /// @param expectedX The expected x-coordinate of the sum
    /// @param expectedY The expected y-coordinate of the sum
    function checkAdd(Point other, bigint expectedX, bigint expectedY) public {
        Point result = ecAdd(this.pt, other);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    /// @notice Multiply the stored point by a scalar and verify the result.
    /// @param scalar The scalar multiplier
    /// @param expectedX The expected x-coordinate of the product
    /// @param expectedY The expected y-coordinate of the product
    function checkMul(bigint scalar, bigint expectedX, bigint expectedY) public {
        Point result = ecMul(this.pt, scalar);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    /// @notice Multiply the generator point G by a scalar and verify the result.
    /// @param scalar The scalar multiplier
    /// @param expectedX The expected x-coordinate
    /// @param expectedY The expected y-coordinate
    function checkMulGen(bigint scalar, bigint expectedX, bigint expectedY) public {
        Point result = ecMulGen(scalar);
        require(ecPointX(result) == expectedX);
        require(ecPointY(result) == expectedY);
    }

    /// @notice Negate the stored point and verify the result's y-coordinate.
    /// @param expectedNegY The expected y-coordinate of the negated point
    function checkNegate(bigint expectedNegY) public {
        Point neg = ecNegate(this.pt);
        require(ecPointY(neg) == expectedNegY);
    }

    /// @notice Verify that negating a point twice returns the original point.
    /// @dev Demonstrates the involution property: -(-P) = P.
    function checkNegateRoundtrip() public {
        Point neg1 = ecNegate(this.pt);
        Point neg2 = ecNegate(neg1);
        require(ecPointX(neg2) == ecPointX(this.pt));
        require(ecPointY(neg2) == ecPointY(this.pt));
    }

    /// @notice Perform modular reduction and verify the result.
    /// @param value The value to reduce
    /// @param modulus The modulus
    /// @param expected The expected result
    function checkModReduce(bigint value, bigint modulus, bigint expected) public {
        require(ecModReduce(value, modulus) == expected);
    }

    /// @notice Compress the stored point to 33-byte public key format and verify.
    /// @param expected The expected compressed encoding
    function checkEncodeCompressed(ByteString expected) public {
        ByteString compressed = ecEncodeCompressed(this.pt);
        require(compressed == expected);
    }

    /// @notice Verify that scalar multiplication by 1 is the identity operation.
    /// @dev For any point P: 1 * P = P.
    function checkMulIdentity() public {
        Point result = ecMul(this.pt, 1);
        require(ecPointX(result) == ecPointX(this.pt));
        require(ecPointY(result) == ecPointY(this.pt));
    }

    /// @notice Verify that the result of ecAdd lies on the curve.
    /// @param other The second point to add
    function checkAddOnCurve(Point other) public {
        Point result = ecAdd(this.pt, other);
        require(ecOnCurve(result));
    }

    /// @notice Verify that a generator multiplication result lies on the curve.
    /// @param scalar The scalar multiplier
    function checkMulGenOnCurve(bigint scalar) public {
        Point result = ecMulGen(scalar);
        require(ecOnCurve(result));
    }
}
