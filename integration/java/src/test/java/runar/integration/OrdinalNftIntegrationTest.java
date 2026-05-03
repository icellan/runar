package runar.integration;

import java.util.ArrayList;
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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * OrdinalNFT integration test -- stateless 1sat-ordinal P2PKH-style
 * contract gating an inscription by a public-key hash.
 *
 * <p>Ported from {@code integration/ts/ordinal-nft.test.ts}.
 */
class OrdinalNftIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/ordinal-nft/OrdinalNFT.runar.ts";

    @Test
    @DisplayName("deploy with owner pubKeyHash")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(owner.pubKeyHash()));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 5_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("unlock with owner key succeeds")
    void unlockSucceeds() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(owner.pubKeyHash()));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null); // sig auto-computed
        args.add(null); // pubKey auto-filled by SDK
        RunarContract.CallOutcome out = contract.call(
            "unlock", args, null, provider, owner.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("wrong owner rejected")
    void wrongOwnerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(owner.pubKeyHash()));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("unlock", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface OrdinalNFT matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/ordinal-nft/OrdinalNFT.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
