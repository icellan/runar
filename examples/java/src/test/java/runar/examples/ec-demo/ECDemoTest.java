package runar.examples.ecdemo;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.MockCrypto.Point;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for ECDemo. Exercises every secp256k1
 * EC built-in by computing the expected output off-chain (via
 * {@link MockCrypto}) and asserting the contract's checks pass.
 */
class ECDemoTest {

    // Use k=7 so the point is a known small-scalar multiple of G.
    private static final BigInteger K = BigInteger.valueOf(7);
    private static final Point PT = MockCrypto.ecMulGen(K);
    private static final BigInteger PT_X = MockCrypto.ecPointX(PT);
    private static final BigInteger PT_Y = MockCrypto.ecPointY(PT);

    // A second point for addition tests (k=13).
    private static final BigInteger K2 = BigInteger.valueOf(13);
    private static final Point PT2 = MockCrypto.ecMulGen(K2);

    @Test
    void contractInstantiates() {
        ECDemo c = new ECDemo(PT);
        assertNotNull(c);
        assertEquals(PT, c.pt);
    }

    @Test
    void checkXMatches() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkX", PT_X);
    }

    @Test
    void checkXWrongFails() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("checkX", PT_X.add(BigInteger.ONE)));
    }

    @Test
    void checkYMatches() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkY", PT_Y);
    }

    @Test
    void checkMakePointMatches() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkMakePoint", PT_X, PT_Y, PT_X, PT_Y);
    }

    @Test
    void checkOnCurveSucceeds() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkOnCurve");
    }

    @Test
    void checkAddMatches() {
        Point sum = MockCrypto.ecAdd(PT, PT2);
        BigInteger ex = MockCrypto.ecPointX(sum);
        BigInteger ey = MockCrypto.ecPointY(sum);
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkAdd", PT2, ex, ey);
    }

    @Test
    void checkMulMatches() {
        BigInteger scalar = BigInteger.valueOf(42);
        Point expected = MockCrypto.ecMul(PT, scalar);
        BigInteger ex = MockCrypto.ecPointX(expected);
        BigInteger ey = MockCrypto.ecPointY(expected);
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkMul", scalar, ex, ey);
    }

    @Test
    void checkMulGenMatches() {
        BigInteger scalar = BigInteger.valueOf(99);
        Point expected = MockCrypto.ecMulGen(scalar);
        BigInteger ex = MockCrypto.ecPointX(expected);
        BigInteger ey = MockCrypto.ecPointY(expected);
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkMulGen", scalar, ex, ey);
    }

    @Test
    void checkNegateMatches() {
        Point neg = MockCrypto.ecNegate(PT);
        BigInteger negY = MockCrypto.ecPointY(neg);
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkNegate", negY);
    }

    @Test
    void checkNegateRoundtripSucceeds() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkNegateRoundtrip");
    }

    @Test
    void checkModReducePositive() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkModReduce", BigInteger.valueOf(17), BigInteger.valueOf(5), BigInteger.valueOf(2));
    }

    @Test
    void checkModReduceNegative() {
        // ecModReduce always returns non-negative for positive modulus.
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkModReduce", BigInteger.valueOf(-3), BigInteger.valueOf(5), BigInteger.valueOf(2));
    }

    @Test
    void checkEncodeCompressedMatches() {
        ByteString expected = MockCrypto.ecEncodeCompressed(PT);
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkEncodeCompressed", expected);
    }

    @Test
    void checkMulIdentitySucceeds() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkMulIdentity");
    }

    @Test
    void checkAddOnCurveSucceeds() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkAddOnCurve", PT2);
    }

    @Test
    void checkMulGenOnCurveSucceeds() {
        ECDemo c = new ECDemo(PT);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("checkMulGenOnCurve", BigInteger.valueOf(12345));
    }
}
