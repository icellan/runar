package runar.integration.helpers;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;

/**
 * Shared setup for on-chain integration tests. Extend this class to
 * pick up the {@link RequiresIntegration} gate and the regtest-safety
 * check.
 *
 * <p>All tests are disabled by default so {@code gradle test} in a
 * CI environment without a running node is a no-op. Enable with:
 *
 * <pre>
 *     gradle test -Drunar.integration=true
 * </pre>
 *
 * <p>The {@link #ensureNode()} pre-flight first guards on the
 * {@code runar.integration} system property via {@link Assumptions#assumeTrue}
 * so that subclasses are reported as <em>skipped</em> (not errored) when the
 * flag is unset — independent of whether JUnit 5 chooses to honour the
 * class-level {@link RequiresIntegration} meta-annotation declared on this
 * abstract base. It then refuses to run on mainnet or testnet even when the
 * caller supplies {@code -Drunar.integration=true}, matching the equivalent
 * {@code conftest.py::ensure_regtest} in the Python suite.
 */
@Tag("integration")
@RequiresIntegration
public abstract class IntegrationBase {

    protected static RpcClient rpc;

    @BeforeAll
    public static void ensureNode() {
        // Belt-and-suspenders gate: JUnit 5 does not always honour
        // class-level @EnabledIfSystemProperty meta-annotations declared
        // on an abstract superclass for the concrete subclass test
        // descriptor (observed under JUnit Jupiter 5.10.2). Re-checking
        // the property here in @BeforeAll guarantees the integration
        // suite is skipped — not errored — when the flag is unset.
        String enabled = System.getProperty("runar.integration", "false");
        Assumptions.assumeTrue(
            "true".equalsIgnoreCase(enabled),
            "Integration tests disabled (set -Drunar.integration=true to enable)."
        );

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
