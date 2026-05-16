package runar.examples.fixedarraynested;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface + simulator tests for the FixedArray-backed {@link Grid2x2}
 * v2 contract. Mirrors the Python pytest acceptance test for the
 * fixed-array-nested example.
 *
 * <p>Per the Java parse-time limitation documented in
 * {@link Grid2x2}'s javadoc, this contract is exercised only through the
 * {@link ContractSimulator}; codegen-level conformance for nested
 * FixedArray state is gated by the 6 non-Java compiler tiers.
 */
class Grid2x2V2Test {

    @Test
    void contractInstantiatesWithZeroGrid() {
        Grid2x2 c = new Grid2x2();
        assertNotNull(c);
        assertEquals(2, c.grid.length());
        assertEquals(2, c.grid.get(0).length());
        assertEquals(Bigint.ZERO, c.grid.get(0).get(0));
        assertEquals(Bigint.ZERO, c.grid.get(0).get(1));
        assertEquals(Bigint.ZERO, c.grid.get(1).get(0));
        assertEquals(Bigint.ZERO, c.grid.get(1).get(1));
    }

    @Test
    void set00WritesTopLeftLeaf() {
        Grid2x2 c = new Grid2x2();
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("set00", Bigint.of(7));
        assertEquals(Bigint.of(7), c.grid.get(0).get(0));
        // Other leaves untouched
        assertEquals(Bigint.ZERO, c.grid.get(0).get(1));
        assertEquals(Bigint.ZERO, c.grid.get(1).get(0));
        assertEquals(Bigint.ZERO, c.grid.get(1).get(1));
    }

    @Test
    void set01ThenSet10AreIndependent() {
        Grid2x2 c = new Grid2x2();
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("set01", Bigint.of(3));
        sim.call("set10", Bigint.of(5));
        assertEquals(Bigint.ZERO, c.grid.get(0).get(0));
        assertEquals(Bigint.of(3), c.grid.get(0).get(1));
        assertEquals(Bigint.of(5), c.grid.get(1).get(0));
        assertEquals(Bigint.ZERO, c.grid.get(1).get(1));
    }

    @Test
    void set11WritesBottomRightLeaf() {
        Grid2x2 c = new Grid2x2();
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("set11", Bigint.of(42));
        assertEquals(Bigint.of(42), c.grid.get(1).get(1));
    }

    @Test
    void read00DoesNotMutateState() {
        Grid2x2 c = new Grid2x2();
        ContractSimulator sim = ContractSimulator.stateful(c);
        sim.call("set00", Bigint.of(9));
        sim.call("read00");
        assertEquals(Bigint.of(9), c.grid.get(0).get(0));
    }
}
