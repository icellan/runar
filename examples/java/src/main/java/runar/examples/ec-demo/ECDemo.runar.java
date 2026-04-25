package runar.examples.ecdemo;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.ByteString;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.ecAdd;
import static runar.lang.Builtins.ecEncodeCompressed;
import static runar.lang.Builtins.ecMakePoint;
import static runar.lang.Builtins.ecModReduce;
import static runar.lang.Builtins.ecMul;
import static runar.lang.Builtins.ecMulGen;
import static runar.lang.Builtins.ecNegate;
import static runar.lang.Builtins.ecOnCurve;
import static runar.lang.Builtins.ecPointX;
import static runar.lang.Builtins.ecPointY;

/**
 * ECDemo -- a stateless contract demonstrating every built-in elliptic
 * curve primitive available in Rúnar.
 *
 * <p>Rúnar provides 10 built-in functions for secp256k1 elliptic curve
 * arithmetic. These compile into Bitcoin Script opcodes that perform
 * real EC math on-chain.
 *
 * <p>Curve: secp256k1
 * <ul>
 *   <li>Field prime p = 2^256 - 2^32 - 977</li>
 *   <li>Group order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141</li>
 *   <li>Generator point G is a fixed curve point; {@code ecMulGen(k)} computes k*G</li>
 *   <li>Points are 64 bytes: x[32] || y[32], big-endian unsigned, no prefix byte</li>
 * </ul>
 *
 * <p>This contract is stateless ({@link SmartContract}); each method is
 * an independent spending condition. No signature checks are performed
 * -- the focus is purely on demonstrating EC operations.
 */
class ECDemo extends SmartContract {

    Point pt;

    ECDemo(Point pt) {
        super(pt);
        this.pt = pt;
    }

    // -------------------------------------------------------------------
    // Coordinate extraction and construction
    // -------------------------------------------------------------------

    /** Verify the stored point's x-coordinate matches {@code expectedX}. */
    @Public
    void checkX(BigInteger expectedX) {
        assertThat(ecPointX(this.pt).equals(expectedX));
    }

    /** Verify the stored point's y-coordinate matches {@code expectedY}. */
    @Public
    void checkY(BigInteger expectedY) {
        assertThat(ecPointY(this.pt).equals(expectedY));
    }

    /** Construct a point from coordinates and verify both coordinates. */
    @Public
    void checkMakePoint(BigInteger x, BigInteger y, BigInteger expectedX, BigInteger expectedY) {
        Point p = ecMakePoint(x, y);
        assertThat(ecPointX(p).equals(expectedX));
        assertThat(ecPointY(p).equals(expectedY));
    }

    // -------------------------------------------------------------------
    // Curve membership
    // -------------------------------------------------------------------

    /** Verify the stored point lies on the secp256k1 curve. */
    @Public
    void checkOnCurve() {
        assertThat(ecOnCurve(this.pt));
    }

    // -------------------------------------------------------------------
    // Point arithmetic
    // -------------------------------------------------------------------

    /** Add the stored point to {@code other} and verify the result. */
    @Public
    void checkAdd(Point other, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecAdd(this.pt, other);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    /** Multiply the stored point by {@code scalar} and verify. */
    @Public
    void checkMul(BigInteger scalar, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecMul(this.pt, scalar);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    /** Multiply the generator point G by {@code scalar} and verify. */
    @Public
    void checkMulGen(BigInteger scalar, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecMulGen(scalar);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    // -------------------------------------------------------------------
    // Point negation
    // -------------------------------------------------------------------

    /** Negate the stored point and verify the resulting y-coordinate. */
    @Public
    void checkNegate(BigInteger expectedNegY) {
        Point neg = ecNegate(this.pt);
        assertThat(ecPointY(neg).equals(expectedNegY));
    }

    /** Negate twice and verify the result equals the original point. */
    @Public
    void checkNegateRoundtrip() {
        Point neg1 = ecNegate(this.pt);
        Point neg2 = ecNegate(neg1);
        assertThat(ecPointX(neg2).equals(ecPointX(this.pt)));
        assertThat(ecPointY(neg2).equals(ecPointY(this.pt)));
    }

    // -------------------------------------------------------------------
    // Modular arithmetic
    // -------------------------------------------------------------------

    /** Verify {@code ecModReduce(value, modulus) == expected}. */
    @Public
    void checkModReduce(BigInteger value, BigInteger modulus, BigInteger expected) {
        assertThat(ecModReduce(value, modulus).equals(expected));
    }

    // -------------------------------------------------------------------
    // Compressed encoding
    // -------------------------------------------------------------------

    /** Verify the 33-byte compressed encoding of the stored point. */
    @Public
    void checkEncodeCompressed(ByteString expected) {
        ByteString compressed = ecEncodeCompressed(this.pt);
        assertThat(compressed.equals(expected));
    }

    // -------------------------------------------------------------------
    // Algebraic properties
    // -------------------------------------------------------------------

    /** Verify {@code 1 * P == P}. */
    @Public
    void checkMulIdentity() {
        Point result = ecMul(this.pt, BigInteger.ONE);
        assertThat(ecPointX(result).equals(ecPointX(this.pt)));
        assertThat(ecPointY(result).equals(ecPointY(this.pt)));
    }

    /** Verify {@code ecAdd(this.pt, other)} lies on the curve. */
    @Public
    void checkAddOnCurve(Point other) {
        Point result = ecAdd(this.pt, other);
        assertThat(ecOnCurve(result));
    }

    /** Verify {@code k*G} lies on the curve. */
    @Public
    void checkMulGenOnCurve(BigInteger scalar) {
        Point result = ecMulGen(scalar);
        assertThat(ecOnCurve(result));
    }
}
