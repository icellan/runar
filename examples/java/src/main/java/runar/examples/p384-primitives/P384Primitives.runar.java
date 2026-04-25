package runar.examples.p384primitives;

import java.math.BigInteger;

import runar.lang.SmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.P384Point;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.p384Add;
import static runar.lang.Builtins.p384Mul;
import static runar.lang.Builtins.p384MulGen;
import static runar.lang.Builtins.p384OnCurve;

/**
 * P384Primitives -- conformance fixture for the NIST P-384 (secp384r1)
 * EC primitives. Mirrors {@link runar.examples.p256primitives.P256Primitives}
 * but at the larger 96-byte point size.
 */
class P384Primitives extends SmartContract {

    @Readonly P384Point expectedPoint;

    P384Primitives(P384Point expectedPoint) {
        super(expectedPoint);
        this.expectedPoint = expectedPoint;
    }

    @Public
    void verify(BigInteger k, P384Point basePoint) {
        P384Point result = p384Mul(basePoint, k);
        assertThat(p384OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }

    @Public
    void verifyAdd(P384Point a, P384Point b) {
        P384Point result = p384Add(a, b);
        assertThat(p384OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }

    @Public
    void verifyMulGen(BigInteger k) {
        P384Point result = p384MulGen(k);
        assertThat(p384OnCurve(result));
        assertThat(result.equals(this.expectedPoint));
    }
}
