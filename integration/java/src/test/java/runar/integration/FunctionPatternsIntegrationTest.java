package runar.integration;

import java.math.BigInteger;
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
 * End-to-end regtest tests for {@code FunctionPatterns} -- a stateful
 * contract demonstrating private methods, built-ins, and method
 * composition. Ported from
 * {@code integration/python/test_function_patterns.py}.
 */
class FunctionPatternsIntegrationTest extends IntegrationBase {

    private static final String SOURCE =
        "examples/ts/function-patterns/FunctionPatterns.runar.ts";

    @Test
    @DisplayName("deploy with owner + initial balance")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(1000)
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 10_000L);
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("deposit succeeds when called by owner")
    void depositSucceeds() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(100)
        ));
        contract.deploy(provider, owner.signer(), 10_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null); // sig auto-computed
        args.add(BigInteger.valueOf(50));
        RunarContract.CallOutcome call = contract.call(
            "deposit", args, null, provider, owner.signer()
        );
        assertNotNull(call.txid());
    }

    @Test
    @DisplayName("deposit then withdraw chain")
    void depositThenWithdraw() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(1000)
        ));
        contract.deploy(provider, owner.signer(), 10_000L);

        ArrayList<Object> deposit = new ArrayList<>();
        deposit.add(null);
        deposit.add(BigInteger.valueOf(500));
        contract.call("deposit", deposit, null, provider, owner.signer());

        ArrayList<Object> withdraw = new ArrayList<>();
        withdraw.add(null);
        withdraw.add(BigInteger.valueOf(200));
        withdraw.add(BigInteger.valueOf(100)); // feeBps
        contract.call("withdraw", withdraw, null, provider, owner.signer());
    }

    @Test
    @DisplayName("wrong owner rejected")
    void wrongOwnerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(100)
        ));
        contract.deploy(provider, owner.signer(), 10_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        args.add(BigInteger.valueOf(50));
        assertThrows(RuntimeException.class, () ->
            contract.call("deposit", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface FunctionPatterns matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/function-patterns/FunctionPatterns.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
