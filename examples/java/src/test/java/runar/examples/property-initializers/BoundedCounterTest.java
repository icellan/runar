package runar.examples.propertyinitializers;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Surface + simulator tests for BoundedCounter. Exercises property
 * initializers (count = 0, active = true) and the bound-check assert
 * in the increment body.
 */
class BoundedCounterTest {

    @Test
    void initializedFieldsHaveDefaults() {
        BoundedCounter c = new BoundedCounter(Bigint.of(10));
        assertEquals(Bigint.ZERO, c.count);
        assertTrue(c.active);
        assertEquals(Bigint.of(10), c.maxCount);
    }

    @Test
    void incrementAccumulatesUpToMaxCount() {
        BoundedCounter c = new BoundedCounter(Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment", Bigint.of(3));
        sim.call("increment", Bigint.of(4));
        assertEquals(Bigint.of(7), c.count);
    }

    @Test
    void incrementPastMaxCountFails() {
        BoundedCounter c = new BoundedCounter(Bigint.of(5));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment", Bigint.of(3));
        assertThrows(AssertionError.class, () -> sim.call("increment", Bigint.of(3)));
    }

    @Test
    void resetZeroesCount() {
        BoundedCounter c = new BoundedCounter(Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment", Bigint.of(4));
        sim.call("reset");
        assertEquals(Bigint.ZERO, c.count);
    }
}
