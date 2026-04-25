package runar.examples.sha256compress;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface tests for Sha256CompressTest. The {@code sha256Compress}
 * builtin is not implemented in the Java simulator (it requires a
 * SHA-256 compression-function port; the contract is exercised via
 * the compiler+VM path instead). We confirm instantiation here and
 * that the simulator surfaces the unimplemented-builtin signal.
 */
class Sha256CompressTestTest {

    @Test
    void contractInstantiates() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        Sha256CompressTest c = new Sha256CompressTest(expected);
        assertNotNull(c);
        assertEquals(expected, c.expected);
    }

    @Test
    void simulatorSurfacesUnimplementedBuiltin() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        ByteString state = ByteString.fromHex("00".repeat(32));
        ByteString block = ByteString.fromHex("00".repeat(64));
        Sha256CompressTest c = new Sha256CompressTest(expected);
        ContractSimulator sim = ContractSimulator.stateless(c);
        // MockCrypto.sha256Compress throws UnsupportedOperationException.
        assertThrows(
            UnsupportedOperationException.class,
            () -> sim.call("verify", state, block)
        );
    }
}
