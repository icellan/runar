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
import runar.lang.sdk.UTXO;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        // A negative test must prove the NODE rejected this spend. The SDK
        // throws the same RuntimeException for a build-time refusal or a
        // UTXO-fetch failure, so record the broadcast count and assert the
        // failing call actually reached consensus.
        int broadcastsBefore0 = provider.broadcastAttempts();
        assertThrows(RuntimeException.class, () ->
            contract.call("send", args, null, provider, attacker.signer())
        );
        assertTrue(provider.broadcastAttempts() > broadcastsBefore0,
            "the rejected call must have been broadcast to the node, not refused by the SDK");
    }

    @Test
    @DisplayName("merge two token UTXOs into one on-chain")
    void merge() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 2.0);
        String tokenId = hexAscii("MERGE-TOKEN");
        BigInteger b1 = BigInteger.valueOf(400);
        BigInteger b2 = BigInteger.valueOf(600);
        long outputSats = 4_000L;

        RunarContract c1 = new RunarContract(a, List.of(
            owner.pubKeyHex(), b1, BigInteger.ZERO, tokenId));
        c1.deploy(provider, owner.signer(), 5_000L);
        RunarContract c2 = new RunarContract(a, List.of(
            owner.pubKeyHex(), b2, BigInteger.ZERO, tokenId));
        c2.deploy(provider, owner.signer(), 5_000L);

        // merge(sig, otherBalance, allPrevouts, otherParentTx, outputSatoshis).
        // Input 0 reports input 1's balance and vice versa; hashOutputs forces
        // both inputs to commit to the same output, which is what makes the merge safe.
        UTXO utxo1 = c1.currentUtxo();
        UTXO utxo2 = c2.currentUtxo();
        String parent1 = provider.getRawTransaction(utxo1.txid());
        String parent2 = provider.getRawTransaction(utxo2.txid());

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);                          // sig: auto-signed
        args.add(b2);                            // otherBalance as seen by input 0
        args.add(null);                          // allPrevouts: auto-computed
        args.add(parent2);
        args.add(BigInteger.valueOf(outputSats));

        ArrayList<Object> input1Args = new ArrayList<>();
        input1Args.add(null);
        input1Args.add(b1);                      // otherBalance as seen by input 1
        input1Args.add(null);
        input1Args.add(parent1);
        input1Args.add(BigInteger.valueOf(outputSats));

        // The continuation state must be stated explicitly, exactly as the TS,
        // Go and Zig merge tests do. The covenant's output depends on which
        // input it is (`myOutpoint === firstOutpoint`), and that branch cannot
        // be resolved off-chain while the preimage is still a placeholder — so
        // the ANF interpreter's guess is not authoritative here. Input 0 writes
        // (myBalance, otherBalance) = (b1, b2).
        java.util.Map<String, Object> merged = new java.util.LinkedHashMap<>();
        merged.put("owner", owner.pubKeyHex());
        merged.put("balance", b1);
        merged.put("mergeBalance", b2);

        CallOptions opts = new CallOptions(merged, null, null)
            .withAdditionalContractInputs(List.of(c2.currentUtxo()))
            .withAdditionalContractInputArgs(List.of(input1Args));

        RunarContract.CallOutcome out =
            c1.callWithOptions("merge", args, opts, provider, owner.signer());
        assertNotNull(out.txid());
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("merge with an inflated counterparty balance is rejected on-chain")
    void mergeInflatedRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet owner = IntegrationWallet.createFunded(rpc, 2.0);
        String tokenId = hexAscii("MERGE-INFLATE");
        BigInteger b1 = BigInteger.valueOf(400);
        BigInteger b2 = BigInteger.valueOf(600);
        long outputSats = 4_000L;

        RunarContract c1 = new RunarContract(a, List.of(
            owner.pubKeyHex(), b1, BigInteger.ZERO, tokenId));
        c1.deploy(provider, owner.signer(), 5_000L);
        RunarContract c2 = new RunarContract(a, List.of(
            owner.pubKeyHex(), b2, BigInteger.ZERO, tokenId));
        c2.deploy(provider, owner.signer(), 5_000L);

        // Supply inflation: input 0 claims its partner holds 1600 (really 600),
        // input 1 claims ITS partner holds 1400 (really 400), which between them
        // would mint 1000 tokens from nothing. The two inputs then compute
        // different outputs, and hashOutputs forces one output set, so the node
        // rejects. Mirrors the Go and Zig tiers' equivalents.
        UTXO utxo1 = c1.currentUtxo();
        UTXO utxo2 = c2.currentUtxo();
        String parent1 = provider.getRawTransaction(utxo1.txid());
        String parent2 = provider.getRawTransaction(utxo2.txid());

        ArrayList<Object> args = new ArrayList<>();
        args.add(null);
        args.add(BigInteger.valueOf(1600));
        args.add(null);
        args.add(parent2);
        args.add(BigInteger.valueOf(outputSats));

        ArrayList<Object> input1Args = new ArrayList<>();
        input1Args.add(null);
        input1Args.add(BigInteger.valueOf(1400));
        input1Args.add(null);
        input1Args.add(parent1);
        input1Args.add(BigInteger.valueOf(outputSats));

        java.util.Map<String, Object> lied = new java.util.LinkedHashMap<>();
        lied.put("owner", owner.pubKeyHex());
        lied.put("balance", b1);
        lied.put("mergeBalance", BigInteger.valueOf(1600));

        CallOptions opts = new CallOptions(lied, null, null)
            .withAdditionalContractInputs(List.of(c2.currentUtxo()))
            .withAdditionalContractInputArgs(List.of(input1Args));

        // The `merge` test above is the honest-balance control over this exact
        // setup: it succeeds, so a failure here is the covenant rejecting the
        // lie rather than the SDK declining to build the transaction.
        // A negative test must prove the NODE rejected this spend. The SDK
        // throws the same RuntimeException for a build-time refusal or a
        // UTXO-fetch failure, so record the broadcast count and assert the
        // failing call actually reached consensus.
        int broadcastsBefore1 = provider.broadcastAttempts();
        assertThrows(RuntimeException.class, () ->
            c1.callWithOptions("merge", args, opts, provider, owner.signer()));
        assertTrue(provider.broadcastAttempts() > broadcastsBefore1,
            "the rejected call must have been broadcast to the node, not refused by the SDK");
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
