package runar.examples.sha256compress;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Behavioural tests for {@link Sha256CompressTest}. The contract calls
 * {@code sha256Compress(state, block)} and verifies the result equals
 * an immutable {@code expected} value. Now that
 * {@link MockCrypto#sha256Compress} is implemented, we exercise both
 * the success and failure paths through the simulator.
 */
class Sha256CompressTestTest {

    private static final ByteString IV = new ByteString(MockCrypto.SHA256_IV);
    private static final ByteString BLOCK_ZEROS = new ByteString(new byte[64]);

    @Test
    void contractInstantiates() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        Sha256CompressTest c = new Sha256CompressTest(expected);
        assertNotNull(c);
        assertEquals(expected, c.expected);
    }

    @Test
    void verifyAcceptsCorrectCompressionResult() {
        ByteString actual = MockCrypto.sha256Compress(IV, BLOCK_ZEROS);
        Sha256CompressTest c = new Sha256CompressTest(actual);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("verify", IV, BLOCK_ZEROS);
    }

    @Test
    void verifyRejectsWrongExpected() {
        ByteString wrong = ByteString.fromHex("00".repeat(32));
        Sha256CompressTest c = new Sha256CompressTest(wrong);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class, () -> sim.call("verify", IV, BLOCK_ZEROS));
    }
}
