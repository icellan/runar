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
import runar.lang.sdk.CallOptions;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TicTacToe integration test -- stateful contract with multi-method
 * game flow: deploy, join, move, win/tie/cancel paths.
 *
 * <p>Ported from {@code integration/python/test_tic_tac_toe.py}.
 */
class TicTacToeIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/tic-tac-toe/TicTacToe.runar.ts";

    @Test
    @DisplayName("deploy TicTacToe with player X + bet amount")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet x = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            x.pubKeyHex(), BigInteger.valueOf(5000)
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, x.signer(), 5_000L);
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("Player O joins after deploy")
    void join() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet x = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet o = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            x.pubKeyHex(), BigInteger.valueOf(5000)
        ));
        contract.deploy(provider, x.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(o.pubKeyHex());
        args.add(null); // sig auto-computed
        RunarContract.CallOutcome out = contract.callWithOptions(
            "join", args, new CallOptions(null, null, null, null).withSatoshis(10_000L) /* N-027: the join pays the 5000 bet */, provider, o.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("X makes a center move after O joins")
    void firstMove() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet x = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet o = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            x.pubKeyHex(), BigInteger.valueOf(5000)
        ));
        contract.deploy(provider, x.signer(), 5_000L);

        ArrayList<Object> joinArgs = new ArrayList<>();
        joinArgs.add(o.pubKeyHex());
        joinArgs.add(null);
        contract.callWithOptions("join", joinArgs, new CallOptions(null, null, null, null).withSatoshis(10_000L) /* N-027: the join pays the 5000 bet */, provider, o.signer());

        ArrayList<Object> moveArgs = new ArrayList<>();
        moveArgs.add(BigInteger.valueOf(4));
        moveArgs.add(x.pubKeyHex());
        moveArgs.add(null);
        RunarContract.CallOutcome out = contract.call(
            "move", moveArgs, null, provider, x.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("wrong player rejected by checkSig")
    void wrongPlayerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet x = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet o = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            x.pubKeyHex(), BigInteger.valueOf(5000)
        ));
        contract.deploy(provider, x.signer(), 5_000L);

        ArrayList<Object> joinArgs = new ArrayList<>();
        joinArgs.add(o.pubKeyHex());
        joinArgs.add(null);
        contract.callWithOptions("join", joinArgs, new CallOptions(null, null, null, null).withSatoshis(10_000L) /* N-027: the join pays the 5000 bet */, provider, o.signer());

        // It's X's turn, but O attempts the move with O's pubKeyHex.
        ArrayList<Object> moveArgs = new ArrayList<>();
        moveArgs.add(BigInteger.valueOf(4));
        moveArgs.add(o.pubKeyHex());
        moveArgs.add(null);
        // A negative test must prove the NODE rejected this spend. The SDK
        // throws the same RuntimeException for a build-time refusal or a
        // UTXO-fetch failure, so record the broadcast count and assert the
        // failing call actually reached consensus.
        int broadcastsBefore0 = provider.broadcastAttempts();
        assertThrows(RuntimeException.class, () ->
            contract.call("move", moveArgs, null, provider, o.signer())
        );
        assertTrue(provider.broadcastAttempts() > broadcastsBefore0,
            "the rejected call must have been broadcast to the node, not refused by the SDK");
    }

    @Test
    @DisplayName("Java-surface TicTacToe matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/tic-tac-toe/TicTacToe.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
