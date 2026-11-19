package runar.lang.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

/**
 * D12 SECP-F1: the native {@code ecModReduce} mock must match the compiled
 * script, which computes {@code ((v tmod m) + m) tmod m} with TRUNCATED mod
 * (ec-codegen.ts emitEcModReduce) and aborts on m == 0. The mock used
 * {@code BigInteger.mod}, which throws for any m <= 0, so a negative modulus
 * the script accepts (7, -3 -> -2) was refused natively.
 *
 * <p>Proves: the script's values for negative / positive moduli (vectors run
 * on @bsv/sdk Spend in the D12 secp256k1 battery) and the m == 0 abort.
 */
class D12EcModReduceTest {
    private static BigInteger r(long v, long m) {
        return MockCrypto.ecModReduce(BigInteger.valueOf(v), BigInteger.valueOf(m));
    }

    @Test
    void matchesScriptFormula() {
        assertEquals(BigInteger.valueOf(-2), r(7, -3));
        assertEquals(BigInteger.valueOf(-1), r(-7, -3));
        assertEquals(BigInteger.ONE, r(-5, 3));
        assertEquals(BigInteger.ONE, r(7, 3));
        assertEquals(BigInteger.ZERO, r(-6, 3));
    }

    @Test
    void zeroModulusAborts() {
        assertThrows(ArithmeticException.class, () -> r(5, 0));
    }
}
