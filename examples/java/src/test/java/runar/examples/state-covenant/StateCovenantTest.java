package runar.examples.statecovenant;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link StateCovenant}.
 *
 * <p>{@code advanceState} composes Baby Bear field multiplication and
 * SHA-256 Merkle root verification, both of which are part of the
 * Go-only crypto family. The Rúnar Java compiler does not yet ship
 * Stack-IR codegen for them, so a {@code CompileCheck} round-trip is
 * intentionally omitted here. End-to-end conformance is exercised via
 * the other compiler tiers.
 */
class StateCovenantTest {

    @Test
    void contractInstantiates() {
        ByteString stateRoot = ByteString.fromHex("00".repeat(32));
        ByteString verifyingKeyHash = ByteString.fromHex("11".repeat(32));
        StateCovenant c = new StateCovenant(stateRoot, Bigint.ZERO, verifyingKeyHash);
        assertNotNull(c);
    }
}
