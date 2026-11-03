package runar.examples.bitwiseops;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.Bigint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for BitwiseOps. The caller supplies the expected
 * shift / AND / OR / XOR results and the contract checks them (F-167: it used
 * to assert only tautologies, so no input could fail). a = 12, b = 10 are
 * 1-byte operands whose results stay below 0x80, so the simulator's integer
 * semantics agree with the on-chain byte-array opcodes; the on-chain verdict
 * for the same values is pinned by
 * conformance/witnesses/real-crypto/bitwise-ops.json.
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
        BitwiseOps c = new BitwiseOps(Bigint.of(12), Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testShift", Bigint.of(48), Bigint.of(6));
    }

    @Test
    void shiftMethodRejectsWrongResult() {
        BitwiseOps c = new BitwiseOps(Bigint.of(12), Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("testShift", Bigint.of(49), Bigint.of(6)));
        assertThrows(AssertionError.class, () -> sim.call("testShift", Bigint.of(48), Bigint.of(7)));
    }

    @Test
    void bitwiseMethodPassesAssertions() {
        BitwiseOps c = new BitwiseOps(Bigint.of(12), Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("testBitwise", Bigint.of(8), Bigint.of(14), Bigint.of(6));
    }

    @Test
    void bitwiseMethodRejectsWrongResult() {
        BitwiseOps c = new BitwiseOps(Bigint.of(12), Bigint.of(10));
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class,
            () -> sim.call("testBitwise", Bigint.of(14), Bigint.of(8), Bigint.of(6)));
        assertThrows(AssertionError.class,
            () -> sim.call("testBitwise", Bigint.of(8), Bigint.of(14), Bigint.of(7)));
    }
}
