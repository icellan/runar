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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * End-to-end regtest deploy tests for {@code CovenantVault}. Spending
 * a covenant requires constructing outputs that exactly match the
 * contract's covenant assertion -- the SDK's generic {@code call()}
 * cannot produce those today, so the deploy path is the regression
 * surface this test pins.
 *
 * <p>Ported from {@code integration/python/test_covenant_vault.py}.
 */
class CovenantVaultIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/covenant-vault/CovenantVault.runar.ts";

    @Test
    @DisplayName("compile produces a CovenantVault artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("CovenantVault", a.contractName());
    }

    @Test
    @DisplayName("deploy with owner + recipient pubKeyHash + minAmount=1000")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet recipient = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), recipient.pubKeyHash(), BigInteger.valueOf(1000)
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 5_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("deploy with zero minAmount")
    void deployZeroMinAmount() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet recipient = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), recipient.pubKeyHash(), BigInteger.ZERO
        ));
        contract.deploy(provider, funder.signer(), 5_000L);
    }

    @Test
    @DisplayName("Java-surface CovenantVault matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/covenant-vault/CovenantVault.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
