package runar.examples.bitwiseops;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface + simulator tests for BitwiseOps -- just verifies the
 * Bigint-wrapper method lowering accepts the source shape. The method
 * bodies return no value; success means all asserts pass.
 */
class BitwiseOpsTest {

    @Test
    void contractInstantiates() {
        BitwiseOps c = new BitwiseOps(Bigint.of(0xAA), Bigint.of(0x55));
        assertNotNull(c);
        assertEquals(Bigint.of(0xAA), c.a);
        assertEquals(Bigint.of(0x55), c.b);
    }

    @Test
    void shiftMethodPassesAssertions() {
        BitwiseOps c = new BitwiseOps(Bigint.of(0x10), Bigint.of(0x01));
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testShift");
    }

    @Test
    void bitwiseMethodPassesAssertions() {
        BitwiseOps c = new BitwiseOps(Bigint.of(0xFF), Bigint.of(0x0F));
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testBitwise");
    }
}
