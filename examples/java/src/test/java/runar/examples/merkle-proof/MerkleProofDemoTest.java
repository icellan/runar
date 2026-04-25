package runar.examples.merkleproof;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link MerkleProofDemo}.
 *
 * <p>The Merkle builtins are part of the Go-only crypto family -- the
 * Rúnar Java compiler does not yet ship Stack-IR codegen for them, so a
 * {@code CompileCheck} round-trip is intentionally omitted here. End-to-
 * end conformance is exercised through the Go / TS / Rust / Python / Zig
 * / Ruby compilers via the shared conformance suite.
 */
class MerkleProofDemoTest {

    @Test
    void contractInstantiates() {
        ByteString expectedRoot = ByteString.fromHex("00".repeat(32));
        MerkleProofDemo c = new MerkleProofDemo(expectedRoot);
        assertNotNull(c);
    }
}
