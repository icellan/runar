package runar.examples.crosscovenant;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.MockCrypto;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;
import runar.lang.types.Sha256;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Surface + simulator tests for {@link CrossCovenantRef}.
 */
class CrossCovenantRefTest {

    @Test
    void contractInstantiates() {
        Sha256 hash = Sha256.fromHex("00".repeat(32));
        CrossCovenantRef c = new CrossCovenantRef(hash);
        assertNotNull(c);
    }

    @Test
    void verifyAndExtractAcceptsMatchingDigest() {
        // Build a referenced output where bytes [10..42) hold an arbitrary 32-byte state root.
        byte[] referenced = new byte[80];
        byte[] stateRoot = new byte[32];
        for (int i = 0; i < 32; i++) stateRoot[i] = (byte) (i + 1);
        System.arraycopy(stateRoot, 0, referenced, 10, 32);

        byte[] hash = MockCrypto.hash256(referenced);
        CrossCovenantRef c = new CrossCovenantRef(new Sha256(hash));
        ContractSimulator sim = ContractSimulator.stateless(c);

        sim.call(
            "verifyAndExtract",
            new ByteString(referenced),
            new ByteString(stateRoot),
            Bigint.of(10)
        );
    }

    @Test
    void verifyAndExtractRejectsTamperedHash() {
        byte[] referenced = new byte[64];
        byte[] stateRoot = new byte[32];
        System.arraycopy(stateRoot, 0, referenced, 0, 32);

        // sourceScriptHash deliberately wrong (zero digest, while real hash is non-zero).
        Sha256 wrongHash = Sha256.fromHex("00".repeat(32));
        CrossCovenantRef c = new CrossCovenantRef(wrongHash);
        ContractSimulator sim = ContractSimulator.stateless(c);

        assertThrows(
            AssertionError.class,
            () -> sim.call(
                "verifyAndExtract",
                new ByteString(referenced),
                new ByteString(stateRoot),
                Bigint.ZERO
            )
        );
    }
}
