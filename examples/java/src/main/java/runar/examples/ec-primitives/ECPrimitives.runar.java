package runar.examples.ecprimitives;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
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
 * ECPrimitives -- conformance fixture exercising every secp256k1
 * elliptic-curve primitive that the Rúnar Java compiler supports.
 *
 * <p>Mirrors {@code conformance/tests/ec-primitives/} so the same
 * Bitcoin Script is emitted regardless of input format.
 */
class ECPrimitives extends SmartContract {

    @Readonly Point pt;

    ECPrimitives(Point pt) {
        super(pt);
        this.pt = pt;
    }

    // Method 0: check x-coordinate extraction
    @Public
    void checkX(BigInteger expectedX) {
        assertThat(ecPointX(this.pt).equals(expectedX));
    }

    // Method 1: check y-coordinate extraction
    @Public
    void checkY(BigInteger expectedY) {
        assertThat(ecPointY(this.pt).equals(expectedY));
    }

    // Method 2: check point is on curve
    @Public
    void checkOnCurve() {
        assertThat(ecOnCurve(this.pt));
    }

    // Method 3: check point negation
    @Public
    void checkNegateY(BigInteger expectedNegY) {
        Point negated = ecNegate(this.pt);
        assertThat(ecPointY(negated).equals(expectedNegY));
    }

    // Method 4: check modular reduction
    @Public
    void checkModReduce(BigInteger value, BigInteger modulus, BigInteger expected) {
        assertThat(ecModReduce(value, modulus).equals(expected));
    }

    // Method 5: check point addition (this.pt + other)
    @Public
    void checkAdd(Point other, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecAdd(this.pt, other);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    // Method 6: check scalar multiplication (this.pt * scalar)
    @Public
    void checkMul(BigInteger scalar, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecMul(this.pt, scalar);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    // Method 7: check generator scalar multiplication (scalar * G)
    @Public
    void checkMulGen(BigInteger scalar, BigInteger expectedX, BigInteger expectedY) {
        Point result = ecMulGen(scalar);
        assertThat(ecPointX(result).equals(expectedX));
        assertThat(ecPointY(result).equals(expectedY));
    }

    // Method 8: check make point roundtrip
    @Public
    void checkMakePoint(BigInteger x, BigInteger y, BigInteger expectedX, BigInteger expectedY) {
        Point pt = ecMakePoint(x, y);
        assertThat(ecPointX(pt).equals(expectedX));
        assertThat(ecPointY(pt).equals(expectedY));
    }

    // Method 9: check compressed encoding
    @Public
    void checkEncodeCompressed(ByteString expected) {
        ByteString compressed = ecEncodeCompressed(this.pt);
        assertThat(compressed.equals(expected));
    }

    // Method 10: check ecMul with scalar=1 (identity — should return same point)
    @Public
    void checkMulIdentity() {
        Point result = ecMul(this.pt, BigInteger.ONE);
        assertThat(ecPointX(result).equals(ecPointX(this.pt)));
        assertThat(ecPointY(result).equals(ecPointY(this.pt)));
    }

    // Method 11: check negate roundtrip (negate twice should return original)
    @Public
    void checkNegateRoundtrip() {
        Point neg1 = ecNegate(this.pt);
        Point neg2 = ecNegate(neg1);
        assertThat(ecPointX(neg2).equals(ecPointX(this.pt)));
        assertThat(ecPointY(neg2).equals(ecPointY(this.pt)));
    }

    // Method 12: check ecOnCurve on a computed point (ecAdd result is on curve)
    @Public
    void checkAddOnCurve(Point other) {
        Point result = ecAdd(this.pt, other);
        assertThat(ecOnCurve(result));
    }

    // Method 13: check ecMulGen result is on curve
    @Public
    void checkMulGenOnCurve(BigInteger scalar) {
        Point result = ecMulGen(scalar);
        assertThat(ecOnCurve(result));
    }
}
