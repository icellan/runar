package runar.examples.merkleproof;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import runar.lang.sdk.CompileCheck;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation + Rúnar frontend round-trip for
 * {@link MerkleProofDemo}.
 *
 * <p>The contract is Rúnar-pure source: arguments flow as
 * {@code Bigint}/{@code ByteString} through {@link runar.lang.Builtins}
 * shims, so the Rúnar Java frontend (parse → validate → typecheck)
 * accepts it via {@link CompileCheck#run(Path)}. Codegen-level
 * conformance for the Merkle (Go-only) crypto family is exercised
 * through the Go / TS / Rust / Python / Zig / Ruby compilers.
 */
class MerkleProofDemoTest {

    @Test
    void contractInstantiates() {
        ByteString expectedRoot = ByteString.fromHex("00".repeat(32));
        MerkleProofDemo c = new MerkleProofDemo(expectedRoot);
        assertNotNull(c);
    }

    @Test
    void compileCheck() {
        Path source = Path.of(
            "src", "main", "java", "runar", "examples", "merkle-proof",
            "MerkleProofDemo.runar.java"
        );
        assertDoesNotThrow(() -> CompileCheck.run(source));
    }
}
