package runar.examples.mathdemo;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for MathDemo. Each test exercises one of
 * the built-in math functions through the off-chain simulator.
 */
class MathDemoTest {

    @Test
    void contractInstantiates() {
        MathDemo c = new MathDemo(BigInteger.TEN);
        assertNotNull(c);
        assertEquals(BigInteger.TEN, c.value);
    }

    @Test
    void divideByHalvesTheValue() {
        MathDemo c = new MathDemo(BigInteger.valueOf(42));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("divideBy", BigInteger.TWO);
        assertEquals(BigInteger.valueOf(21), c.value);
    }

    @Test
    void clampNarrowsToRange() {
        MathDemo c = new MathDemo(BigInteger.valueOf(500));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("clampValue", BigInteger.valueOf(0), BigInteger.valueOf(100));
        assertEquals(BigInteger.valueOf(100), c.value);
    }

    @Test
    void squareRootTakesFloor() {
        MathDemo c = new MathDemo(BigInteger.valueOf(17));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("squareRoot");
        assertEquals(BigInteger.valueOf(4), c.value);
    }

    @Test
    void withdrawRejectsOverdraft() {
        MathDemo c = new MathDemo(BigInteger.valueOf(100));
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(
            AssertionError.class,
            () -> sim.call("withdrawWithFee", BigInteger.valueOf(200), BigInteger.valueOf(100))
        );
    }
}
