package runar.examples.sha256finalize;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface tests for Sha256FinalizeTest. The {@code sha256Finalize}
 * builtin is not implemented in the Java simulator (it requires a
 * SHA-256 compression-function port). We confirm instantiation here
 * and that the simulator surfaces the unimplemented-builtin signal.
 */
class Sha256FinalizeTestTest {

    @Test
    void contractInstantiates() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        Sha256FinalizeTest c = new Sha256FinalizeTest(expected);
        assertNotNull(c);
        assertEquals(expected, c.expected);
    }

    @Test
    void simulatorSurfacesUnimplementedBuiltin() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        ByteString state = ByteString.fromHex("00".repeat(32));
        ByteString remaining = ByteString.fromHex("00".repeat(16));
        Sha256FinalizeTest c = new Sha256FinalizeTest(expected);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(
            UnsupportedOperationException.class,
            () -> sim.call("verify", state, remaining, BigInteger.valueOf(128))
        );
    }
}
