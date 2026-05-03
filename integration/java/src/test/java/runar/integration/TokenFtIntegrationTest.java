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
 * FungibleToken integration test -- stateful contract with addOutput.
 *
 * <p>Ported from {@code integration/python/test_fungible_token.py}.
 * Constructor: {@code (owner: PubKey, balance: bigint, mergeBalance: bigint, tokenId: ByteString)}.
 */
class TokenFtIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/token-ft/FungibleTokenExample.runar.ts";

    private static String hexAscii(String s) {
        StringBuilder sb = new StringBuilder(s.length() * 2);
        for (char c : s.toCharArray()) sb.append(String.format("%02x", (int) c & 0xff));
        return sb.toString();
    }

    @Test
    @DisplayName("compile produces a FungibleToken artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("FungibleToken", a.contractName());
    }

    @Test
    @DisplayName("deploy with owner + balance + tokenId")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(1000), BigInteger.ZERO,
            hexAscii("TEST-TOKEN-001")
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 5_000L);
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("send entire balance to a recipient")
    void send() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet recipient = IntegrationWallet.create();

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(1000), BigInteger.ZERO,
            hexAscii("SEND-TOKEN")
        ));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null); // sig auto-computed
        args.add(recipient.pubKeyHex());
        args.add(BigInteger.valueOf(5000));
        RunarContract.CallOutcome out = contract.call(
            "send", args, null, provider, owner.signer()
        );
        assertNotNull(out.txid());
    }

    @Test
    @DisplayName("send by wrong owner rejected")
    void wrongOwnerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet recipient = IntegrationWallet.create();

        RunarContract contract = new RunarContract(a, List.of(
            owner.pubKeyHex(), BigInteger.valueOf(1000), BigInteger.ZERO,
            hexAscii("REJECT-TOKEN")
        ));
        contract.deploy(provider, owner.signer(), 5_000L);

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        args.add(recipient.pubKeyHex());
        args.add(BigInteger.valueOf(5000));
        assertThrows(RuntimeException.class, () ->
            contract.call("send", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface FungibleToken matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/token-ft/FungibleTokenExample.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
