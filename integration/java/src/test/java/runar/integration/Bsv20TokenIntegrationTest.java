package runar.integration;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;
import runar.lang.sdk.ordinals.Bsv20;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * BSV-20 token integration test -- fungible token inscriptions on a
 * P2PKH-style locking script. Exercises {@code Bsv20.deploy/mint/transfer}
 * inscription helpers in the Java SDK alongside {@code RunarContract}.
 *
 * <p>Ported from {@code integration/ts/bsv20-token.test.ts} (subset).
 */
class Bsv20TokenIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/bsv20-token/BSV20Token.runar.ts";

    @Test
    @DisplayName("deploy a BSV-20 token (deploy inscription envelope)")
    void deployBsv20() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(wallet.pubKeyHash()))
            .withInscription(Bsv20.deploy("RUNAR", "21000000", "1000", "0"));

        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 1L);
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("mint BSV-20 tokens")
    void mintBsv20() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(wallet.pubKeyHash()))
            .withInscription(Bsv20.mint("RUNAR", "1000"));

        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 1L);
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface BSV20Token matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/bsv20-token/BSV20Token.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
