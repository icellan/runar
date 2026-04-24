package runar.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.RpcClient;
import runar.lang.sdk.LocalSigner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Smoke tests that always run (no node required) to prove the Gradle
 * composite build is wired correctly and the helper classes load.
 *
 * <p>Full regtest / Teranode tests are gated behind the
 * {@code -Drunar.integration=true} system property — see
 * {@link runar.integration.helpers.IntegrationBase}. This class is
 * intentionally <b>not</b> gated so a bare {@code gradle test} from the
 * project root exercises at least the wiring.
 */
class WiringSmokeTest {

    @Test
    @DisplayName("RpcClient picks the right default URL per backend")
    void rpcClientDefaults() {
        // The client reads env at construction time; in a CI harness with no
        // env vars set, the default backend is svnode -> localhost:18332.
        RpcClient rpc = new RpcClient();
        assertNotNull(rpc.backend());
        assertNotNull(rpc.url());
        assertTrue(
            rpc.url().contains("18332") || rpc.url().contains("19292"),
            "RpcClient default URL should be regtest bitcoind or Teranode RPC, got: " + rpc.url()
        );
    }

    @Test
    @DisplayName("Project root resolves from the Gradle working directory")
    void projectRootResolves() {
        var root = ContractCompiler.projectRoot();
        assertNotNull(root);
        // The project root must contain the runar-java SDK sources — this is
        // the invariant IntegrationBase + ContractCompiler rely on.
        assertTrue(
            java.nio.file.Files.isDirectory(root.resolve("packages/runar-java")),
            "projectRoot() must contain packages/runar-java, got " + root
        );
    }

    @Test
    @DisplayName("LocalSigner from a 32-byte hex key is deterministic")
    void localSignerBasics() {
        LocalSigner s = new LocalSigner(
            "0000000000000000000000000000000000000000000000000000000000000001"
        );
        assertNotNull(s.pubKey());
        assertEquals(33, s.pubKey().length, "compressed pubkey is 33 bytes");
        assertNotNull(s.address());
    }
}
