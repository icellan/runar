package runar.integration;

import java.math.BigInteger;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import runar.integration.helpers.ContractCompiler;
import runar.integration.helpers.IntegrationBase;
import runar.integration.helpers.IntegrationWallet;
import runar.integration.helpers.NodeRejection;
import runar.integration.helpers.RpcProvider;
import runar.lang.sdk.CallOptions;
import runar.lang.sdk.RunarArtifact;
import runar.lang.sdk.RunarContract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    @DisplayName("close: auctioneer signs, non-zero deadline + matching nLockTime → spend accepted")
    void closeSucceeds() {
        RunarArtifact a = ContractCompiler.compileRelative(SOURCE);
        RpcProvider provider = new RpcProvider(rpc);
        IntegrationWallet auctioneer = IntegrationWallet.createFunded(rpc, 1.0);
        IntegrationWallet bidder = IntegrationWallet.create();

        // G5: a REAL non-zero block-height deadline paired with a matching
        // CallOptions.locktime, mirroring integration/rust/tests/auction.rs. The
        // old deadline=0 + nLockTime=0 combination made
        // extractLocktime(preimage) >= deadline vacuously true, so a regression
        // in the SDK's locktime threading (or in extractLocktime codegen) would
        // not have been caught. nLockTime=1 is safely in the past so the tx is
        // immediately mineable — but if the SDK stopped writing the locktime
        // into the preimage, the preimage would carry 0 and 0 >= 1 would fail.
        final int deadline = 1;
        RunarContract contract = new RunarContract(a, List.of(
            auctioneer.pubKeyHex(), bidder.pubKeyHex(),
            BigInteger.valueOf(100), BigInteger.valueOf(deadline)
        ));
        contract.deploy(provider, auctioneer.signer(), 5_000L);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null); // sig auto-computed
        RunarContract.CallOutcome call = contract.callWithOptions(
            "close", args, new CallOptions(null, null, null, deadline),
            provider, auctioneer.signer()
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

        // Non-zero block-height deadline (see closeSucceeds). locktime is set so
        // the ONLY reason for rejection is the wrong signer, not an unsatisfied
        // deadline.
        RunarContract contract = new RunarContract(a, List.of(
            auctioneer.pubKeyHex(), bidder.pubKeyHex(),
            BigInteger.valueOf(100), BigInteger.ONE
        ));
        contract.deploy(provider, auctioneer.signer(), 5_000L);

        java.util.ArrayList<Object> args = new java.util.ArrayList<>();
        args.add(null);
        // A negative test must prove the NODE rejected this spend: an
        // exception plus a moved broadcast counter is not enough, because an
        // ACCEPTED tx whose confirming mine fails throws too (GK-BUG-004).
        NodeRejection.assertNodeRejected(provider, () ->
            contract.callWithOptions(
                "close", args, new CallOptions(null, null, null, 1),
                provider, attacker.signer()
            ),
            NodeRejection.SCRIPT_VERIFY_FAILED);
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
