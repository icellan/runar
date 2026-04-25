package runar.examples.merkleproof;

import org.junit.jupiter.api.Test;
import runar.lang.types.ByteString;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Surface-level instantiation test for {@link MerkleProofDemo}.
 *
 * <p>{@code verifySha256} / {@code verifyHash256} unwrap {@code Bigint}
 * arguments via {@code .value()} for interop with
 * {@link runar.lang.runtime.MockCrypto}. The Rúnar Java frontend does
 * not yet recognise {@code .value()} on {@code Bigint}, so a
 * {@link runar.lang.sdk.CompileCheck} round-trip is skipped for now.
 * Codegen-level conformance is exercised through the Go / TS / Rust /
 * Python / Zig / Ruby compilers.
 */
class MerkleProofDemoTest {

    @Test
    void contractInstantiates() {
        ByteString expectedRoot = ByteString.fromHex("00".repeat(32));
        MerkleProofDemo c = new MerkleProofDemo(expectedRoot);
        assertNotNull(c);
    }
}
