package runar.integration;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * PrivateHelperOutputs integration test — 2026-04-30 audit regression
 * (F1 + F3).
 *
 * <p>The contract delegates state mutation, addDataOutput, and
 * addOutput to private helpers. Before the F1 fix the auto-injection
 * was a shallow scan of the public method body, so these methods
 * were silently classified as terminal and the deploy + call cycle
 * would fail.
 *
 * <p>Mirrors the TS / Go / Rust / Python / Ruby / Zig integration
 * tests for the same contract.
 */
class PrivateHelperOutputsIntegrationTest extends IntegrationBase {

    @Test
    @DisplayName("commit chain: three sequential calls each spend the previous continuation")
    void commitChain() {
        // Failure here means the runtime hashOutputs hash didn't
        // match the compiled continuation — exactly what F1's
        // shallow-scan miss would produce for state-mutation routed
        // through a private helper.
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        for (int i = 0; i < 3; i++) {
            RunarContract.CallOutcome out = contract.call(
                "commit", List.of(), null, provider, wallet.signer()
            );
            assertNotNull(out.txid(), "commit #" + (i + 1) + ": empty txid");
        }
    }

    @Test
    @DisplayName("log() routes a data output through a private helper")
    void logEmitsDataOutput() {
        RunarArtifact artifact = ContractCompiler.compileRelative(
            "examples/ts/private-helper-outputs/PrivateHelperOutputs.runar.ts"
        );

        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(
            artifact, List.of(BigInteger.ZERO)
        );
        contract.deploy(provider, wallet.signer(), 5_000L);

        // OP_RETURN-style payload (0x6a + 7-byte ASCII "hello!").
        String payload = "6a0768656c6c6f21";
        RunarContract.CallOutcome out = contract.call(
            "log", List.of(payload), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }
}
