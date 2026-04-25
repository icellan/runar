package runar.examples.sha256finalize;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Behavioural tests for {@link Sha256FinalizeTest}. The contract calls
 * {@code sha256Finalize(state, remaining, msgBitLen)} and verifies the
 * result equals an immutable {@code expected} digest.
 */
class Sha256FinalizeTestTest {

    private static final ByteString IV = new ByteString(MockCrypto.SHA256_IV);

    @Test
    void contractInstantiates() {
        ByteString expected = ByteString.fromHex("00".repeat(32));
        Sha256FinalizeTest c = new Sha256FinalizeTest(expected);
        assertNotNull(c);
        assertEquals(expected, c.expected);
    }

    @Test
    void verifyAcceptsCorrectFipsAbcDigest() {
        // SHA-256("abc") = ba7816bf...20015ad. Single-block path: state=IV,
        // remaining="abc", msgBitLen=24.
        ByteString expected = ByteString.fromHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        Sha256FinalizeTest c = new Sha256FinalizeTest(expected);
        ContractSimulator sim = ContractSimulator.stateless(c);
        sim.call("verify", IV, new ByteString("abc".getBytes()), BigInteger.valueOf(24));
    }

    @Test
    void verifyRejectsWrongExpected() {
        ByteString wrong = ByteString.fromHex("00".repeat(32));
        Sha256FinalizeTest c = new Sha256FinalizeTest(wrong);
        ContractSimulator sim = ContractSimulator.stateless(c);
        assertThrows(AssertionError.class,
            () -> sim.call("verify", IV, new ByteString("abc".getBytes()), BigInteger.valueOf(24)));
    }
}
