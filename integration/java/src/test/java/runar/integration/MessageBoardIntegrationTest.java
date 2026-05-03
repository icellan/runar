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
 * MessageBoard integration test -- stateful contract with ByteString
 * state. Methods: {@code post(newMessage)} (anyone) and {@code burn(sig)}
 * (owner only, terminal).
 *
 * <p>Ported from {@code integration/ts/message-board.test.ts}.
 */
class MessageBoardIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/message-board/MessageBoard.runar.ts";

    @Test
    @DisplayName("post a message (auto-computed state)")
    void postMessage() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet wallet = IntegrationWallet.createFunded(rpc, 1.0);

        // Constructor: (message: ByteString, owner: PubKey)
        RunarContract contract = new RunarContract(a, List.of("00", wallet.pubKeyHex()));
        contract.deploy(provider, wallet.signer(), 5_000L);

        RunarContract.CallOutcome out = contract.call(
            "post", List.of("48656c6c6f"), null, provider, wallet.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("burn with owner signature")
    void burnByOwner() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of("00", owner.pubKeyHex()));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        RunarContract.CallOutcome out = contract.call(
            "burn", args, null, provider, owner.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("burn rejected with wrong signer")
    void burnWrongSignerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of("00", owner.pubKeyHex()));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("burn", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface MessageBoard matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/message-board/MessageBoard.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
