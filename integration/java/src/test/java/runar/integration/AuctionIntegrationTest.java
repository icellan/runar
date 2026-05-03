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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * End-to-end regtest tests for the {@code Auction} stateful contract.
 * Ported from {@code integration/python/test_auction.py} and
 * {@code integration/go/auction_test.go}.
 *
 * <p>Auction is a StatefulSmartContract with properties: auctioneer
 * (PubKey, readonly), highestBidder (PubKey), highestBid (bigint),
 * deadline (bigint, readonly). Methods: {@code bid(sig, bidder, bidAmount)},
 * {@code close(sig)}.
 */
class AuctionIntegrationTest extends IntegrationBase {

    private static final String SOURCE = "examples/ts/auction/Auction.runar.ts";

    @Test
    @DisplayName("compile produces an Auction artifact")
    void compile() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        assertEquals("Auction", a.contractName());
    }

    @Test
    @DisplayName("deploy with auctioneer + initial bidder + bid + deadline")
    void deploy() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet auctioneer = IntegrationWallet.create();
        IntegrationWallet bidder = IntegrationWallet.create();
        IntegrationWallet funder = IntegrationWallet.createFunded(rpc, 1.0);

        RunarContract contract = new RunarContract(a, List.of(
            auctioneer.pubKeyHex(), bidder.pubKeyHex(),
            BigInteger.valueOf(1000), BigInteger.valueOf(1_000_000)
        ));
        RunarContract.DeployOutcome out = contract.deploy(provider, funder.signer(), 5_000L);
        assertEquals(64, out.txid().length());
    }

    @Test
    @DisplayName("close: auctioneer signs, deadline=0 → spend accepted")
    void closeSucceeds() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet auctioneer = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet bidder = IntegrationWallet.create();

        // deadline=0 makes extractLocktime(preimage) >= deadline always pass.
        RunarContract contract = new RunarContract(a, List.of(
            auctioneer.pubKeyHex(), bidder.pubKeyHex(),
            BigInteger.valueOf(100), BigInteger.ZERO
        ));
        contract.deploy(provider, auctioneer.signer(), 5_000L);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); // sig auto-computed
        RunarContract.CallOutcome call = contract.call(
            "close", args, null, provider, auctioneer.signer()
        );
        assertNotNull(call.txid());
    }

    @Test
    @DisplayName("close: wrong signer rejected by the node")
    void closeWrongSignerRejected() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet auctioneer = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet attacker = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet bidder = IntegrationWallet.create();

        RunarContract contract = new RunarContract(a, List.of(
            auctioneer.pubKeyHex(), bidder.pubKeyHex(),
            BigInteger.valueOf(100), BigInteger.ZERO
        ));
        contract.deploy(provider, auctioneer.signer(), 5_000L);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null);
        assertThrows(RuntimeException.class, () ->
            contract.call("close", args, null, provider, attacker.signer())
        );
    }

    @Test
    @DisplayName("Java-surface Auction matches TS reference")
    void javaSurfaceMatches() {
        RunarArtifact ts = ContractCompiler.compileRelative(SOURCE);
        RunarArtifact java = ContractCompiler.compileRelative(
            "examples/java/src/main/java/runar/examples/auction/Auction.runar.java"
        );
        assertEquals(ts.scriptHex(), java.scriptHex());
    }
}
