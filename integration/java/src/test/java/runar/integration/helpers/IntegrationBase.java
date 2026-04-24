package runar.integration.helpers;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Shared setup for on-chain integration tests. Extend this class to
 * pick up the {@code @EnabledIfSystemProperty(name = "runar.integration",
 * matches = "true")} gate and the regtest-safety check.
 *
 * <p>All tests are disabled by default so {@code gradle test} in a
 * CI environment without a running node is a no-op. Enable with:
 *
 * <pre>
 *     gradle test -Drunar.integration=true
 * </pre>
 *
 * <p>The {@link #ensureNode()} pre-flight refuses to run on mainnet or
 * testnet even if the caller supplies {@code -Drunar.integration=true}
 * — the regtest-only guard matches the equivalent
 * {@code conftest.py::ensure_regtest} in the Python suite.
 */
@Tag("integration")
@EnabledIfSystemProperty(named = "runar.integration", matches = "true")
public abstract class IntegrationBase {

    protected static RpcClient rpc;

    @BeforeAll
    public static void ensureNode() {
        rpc = new RpcClient();
        if (!rpc.isAvailable()) {
            throw new IllegalStateException(
                "Regtest node not reachable at " + rpc.url() + " (backend=" + rpc.backend()
                    + "). Start it with `./integration/regtest.sh start` (svnode) or "
                    + "`./integration/teranode.sh start` (teranode)."
            );
        }
        rpc.ensureRegtest();
        rpc.ensureMatureCoinbase();
    }
}
