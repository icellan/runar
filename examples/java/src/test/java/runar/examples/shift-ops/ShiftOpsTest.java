package runar.examples.shiftops;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The caller supplies the expected shift results and the contract checks them
 * (F-167: it used to assert only tautologies, so no input could fail). With
 * a = 12 the simulator agrees with the on-chain OP_LSHIFT / OP_RSHIFT; the
 * on-chain verdict is pinned by conformance/witnesses/real-crypto/shift-ops.json.
 */
class ShiftOpsTest {

    @Test
    void contractInstantiates() {
        ShiftOps c = new ShiftOps(Bigint.of(8));
        assertNotNull(c);
        assertEquals(Bigint.of(8), c.a);
    }

    @Test
    void shiftMethodPassesAssertions() {
        ShiftOps c = new ShiftOps(Bigint.of(12));
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testShift", Bigint.of(96), Bigint.of(3));
    }

    @Test
    void shiftMethodRejectsWrongResult() {
        ShiftOps c = new ShiftOps(Bigint.of(12));
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("testShift", Bigint.of(97), Bigint.of(3)));
        assertThrows(AssertionError.class, () -> sim.call("testShift", Bigint.of(96), Bigint.of(2)));
    }
}
