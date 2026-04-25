package runar.examples.statecovenant;

import org.junit.jupiter.api.Test;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link StateCovenant}.
 *
 * <p>{@code advanceState} composes Baby Bear field multiplication and
 * SHA-256 Merkle root verification (Go-only crypto family) and unwraps
 * {@code Bigint} via {@code .value()}, which the Rúnar Java frontend
 * does not yet recognise. A {@link runar.lang.sdk.CompileCheck} round-trip
 * is skipped for now; codegen-level conformance is exercised via the
 * other compiler tiers.
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
