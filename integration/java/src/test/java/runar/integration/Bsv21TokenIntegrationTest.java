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
import runar.lang.sdk.ordinals.Bsv21;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * BSV-21 token integration test -- BSV-21 deploy+mint inscriptions on
 * a P2PKH-style locking script. Ported from
 * {@code integration/ts/bsv21-token.test.ts} (deploy subset).
 */
class Bsv21TokenIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/bsv21-token/BSV21Token.runar.ts";

    @Test
    @DisplayName("deploy a BSV-21 token (deploy+mint envelope)")
    void deployBsv21() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(wallet.pubKeyHash()))
            // deployMint(amount, decimals, symbol, icon)
            .withInscription(Bsv21.deployMint("21000000", "0", "RUNAR21", "RUNAR21 Token"));

        RunarContract.DeployOutcome out = contract.deploy(provider, wallet.signer(), 1L);
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("Java-surface BSV21Token matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/bsv21-token/BSV21Token.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
