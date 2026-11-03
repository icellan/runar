package runar.lang.sdk;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

import runar.lang.runtime.MockCrypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * N-183: {@link MockCrypto#ecMakePoint} must apply the compiled script's R-156
 * gate: each coordinate must satisfy 0 &lt;= v &lt; p, or the script aborts.
 * Before the fix it wrapped any BigInteger in a Point and only failed (or
 * truncated) later, in to32.
 *
 * <p>Proves: boundary operands (p, p+1, -1, 2^256 on either half) throw, and
 * p - 1 / 0 / a real curve point still build.
 * <p>Does not prove: the script itself (the runar-testing r156 test pins it).
 */
class N183EcMakePointFieldGateTest {

    private static final BigInteger P = MockCrypto.EC_P;
    private static final BigInteger GY = new BigInteger(
        "4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee", 16);
    private static final BigInteger TWO_256 = BigInteger.ONE.shiftLeft(256);

    private static void refuses(BigInteger x, BigInteger y) {
        assertThrows(RuntimeException.class, () -> MockCrypto.ecMakePoint(x, y),
            "ecMakePoint(" + x + ", " + y + ") must abort as the script does");
    }

    @Test
    void refusesNonFieldElements() {
        refuses(P, GY);
        refuses(P.add(BigInteger.ONE), GY);
        refuses(BigInteger.ONE, P);
        refuses(BigInteger.ONE, P.add(BigInteger.ONE));
        refuses(BigInteger.ONE.negate(), GY);
        refuses(BigInteger.ONE, BigInteger.ONE.negate());
        refuses(TWO_256, GY);
        refuses(BigInteger.ONE, TWO_256.add(BigInteger.ONE));
    }

    @Test
    void stillBuildsFieldElements() {
        BigInteger pm1 = P.subtract(BigInteger.ONE);
        byte[] raw = MockCrypto.ecMakePoint(pm1, pm1).toRaw64();
        byte[] want = new byte[64];
        byte[] c = pm1.toByteArray();
        System.arraycopy(c, c.length - 32, want, 0, 32);
        System.arraycopy(c, c.length - 32, want, 32, 32);
        assertArrayEquals(want, raw);
        MockCrypto.ecMakePoint(BigInteger.ZERO, BigInteger.ZERO);
        MockCrypto.ecMakePoint(BigInteger.ONE, GY);
    }
}
