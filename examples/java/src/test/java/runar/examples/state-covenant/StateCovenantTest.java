package runar.examples.statecovenant;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.Bigint;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation + Rúnar frontend round-trip for
 * {@link StateCovenant}.
 *
 * <p>The contract is Rúnar-pure source: {@code advanceState} composes
 * Baby Bear field multiplication and SHA-256 Merkle root verification
 * via {@link runar.lang.Builtins} shims (Go-only crypto family) using
 * {@code Bigint}/{@code ByteString} throughout, so the Rúnar Java
 * frontend (parse → validate → typecheck) accepts it via
 * {@link CompileCheck#run(Path)}. Codegen-level conformance is exercised
 * through the other compiler tiers.
 */
class StateCovenantTest {

    @Test
    void contractInstantiates() {
        ByteString stateRoot = ByteString.fromHex("00".repeat(32));
        ByteString verifyingKeyHash = ByteString.fromHex("11".repeat(32));
        StateCovenant c = new StateCovenant(stateRoot, Bigint.ZERO, verifyingKeyHash);
        assertNotNull(c);
    }

    @Test
    void compileCheck() {
        Path source = Path.of(
            "src", "main", "java", "runar", "examples", "state-covenant",
            "StateCovenant.runar.java"
        );
        assertDoesNotThrow(() -> CompileCheck.run(source));
    }
}
