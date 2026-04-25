package runar.examples.p256primitives;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.P256Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.p256Add;
import static runar.lang.Builtins.p256Mul;
import static runar.lang.Builtins.p256MulGen;
import static runar.lang.Builtins.p256OnCurve;

/**
 * P256Primitives -- conformance fixture for the NIST P-256 (secp256r1)
 * EC primitives. Each method recomputes the stored {@code expectedPoint}
 * via a different primitive ({@code p256Mul}, {@code p256Add},
 * {@code p256MulGen}) and asserts the result equals the stored value.
 */
class P256Primitives extends SmartContract {

    @Readonly P256Point expectedPoint;

    P256Primitives(P256Point expectedPoint) {
        super(expectedPoint);
        this.expectedPoint = expectedPoint;
    }

    @Public
    void verify(BigInteger k, P256Point basePoint) {
        P256Point result = p256Mul(basePoint, k);
        assertThat(p256OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }

    @Public
    void verifyAdd(P256Point a, P256Point b) {
        P256Point result = p256Add(a, b);
        assertThat(p256OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }

    @Public
    void verifyMulGen(BigInteger k) {
        P256Point result = p256MulGen(k);
        assertThat(p256OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }
}
