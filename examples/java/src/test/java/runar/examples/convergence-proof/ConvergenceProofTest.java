package runar.examples.convergenceproof;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.runtime.SimulatorContext;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for {@link ConvergenceProof}. Exercises the
 * OPRF convergence relation
 * {@code R_A - R_B == delta_o * G} via the EC builtins.
 */
class ConvergenceProofTest {

    @Test
    void contractInstantiates() {
        // Place a couple of toy points; the constructor doesn't validate them.
        MockCrypto.Point a = MockCrypto.ecMakePoint(BigInteger.ONE, BigInteger.TWO);
        MockCrypto.Point b = MockCrypto.ecMakePoint(BigInteger.valueOf(3), BigInteger.valueOf(4));
        ConvergenceProof c = new ConvergenceProof(a, b);
        assertNotNull(c);
    }

    @Test
    void proveConvergenceSucceedsForRealRelation() {
        // Build R_A = a*G, R_B = b*G so that R_A - R_B = (a-b)*G.
        BigInteger a = BigInteger.valueOf(7);
        BigInteger b = BigInteger.valueOf(3);
        SimulatorContext.enter();
        MockCrypto.Point rA;
        MockCrypto.Point rB;
        try {
            rA = MockCrypto.ecMulGen(a);
            rB = MockCrypto.ecMulGen(b);
        } finally {
            SimulatorContext.exit();
        }
        ConvergenceProof c = new ConvergenceProof(rA, rB);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("proveConvergence", Bigint.of(a.subtract(b).longValueExact()));
    }

    @Test
    void proveConvergenceRejectsWrongDelta() {
        BigInteger a = BigInteger.valueOf(11);
        BigInteger b = BigInteger.valueOf(5);
        SimulatorContext.enter();
        MockCrypto.Point rA;
        MockCrypto.Point rB;
        try {
            rA = MockCrypto.ecMulGen(a);
            rB = MockCrypto.ecMulGen(b);
        } finally {
            SimulatorContext.exit();
        }
        ConvergenceProof c = new ConvergenceProof(rA, rB);
        ContractSimulator sim = ContractSimulator.stateless(c);
        // wrong delta: a - b is 6, claim 7 instead.
        assertThrows(AssertionError.class, () -> sim.call("proveConvergence", Bigint.of(7)));
    }
}
