package runar.examples.statefulcounter;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * M12 part 2 surface + simulator tests for the stateful Counter contract.
 * Exercises the Bigint-wrapper arithmetic lowering end-to-end.
 */
class CounterTest {

    @Test
    void contractInstantiatesWithInitialCount() {
        Counter c = new Counter(Bigint.ZERO);
        assertNotNull(c);
        assertEquals(Bigint.ZERO, c.count);
    }

    @Test
    void simulatorIncrementsCount() {
        Counter c = new Counter(Bigint.of(7));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("increment");
        assertEquals(Bigint.of(8), c.count);
    }

    @Test
    void simulatorDecrementsCount() {
        Counter c = new Counter(Bigint.of(3));
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("decrement");
        assertEquals(Bigint.of(2), c.count);
    }

    @Test
    void simulatorRejectsDecrementBelowZero() {
        Counter c = new Counter(Bigint.ZERO);
        ContractSimulator sim = ContractSimulator.stateful(c);
        assertThrows(AssertionError.class, () -> sim.call("decrement"));
    }
}
