package runar.examples.auction;

import java.math.BigInteger;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.Preimage;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuctionTest {

    private static final PubKey AUCTIONEER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey ALICE      = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final PubKey BOB        = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000003");
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

    /**
     * F-129: callStateful checks the preimage against the spending transaction
     * it builds from the compiled contract, so every call here passes the
     * honest preimage ({@code preimageFor}) built from the same spender-chosen
     * fields the test used to hand-roll.
     */
    private static final Path SOURCE = Path.of(
        "src", "main", "java", "runar", "examples", "auction", "Auction.runar.java"
    );

    @Test
    void contractInstantiates() {
        Auction a = new Auction(AUCTIONEER, AUCTIONEER, Bigint.ZERO, Bigint.of(1_000_000));
        assertNotNull(a);
        assertEquals(AUCTIONEER, a.auctioneer);
        assertEquals(Bigint.ZERO, a.highestBid);
    }

    @Test
    void bidAcceptsHigherBidBeforeDeadline() {
        Auction a = new Auction(AUCTIONEER, AUCTIONEER, Bigint.ZERO, Bigint.of(1_000_000));
        ContractSimulator sim = ContractSimulator.stateful(a, SOURCE);
        // N-027: continuationAmount() is 10000 off-chain, so a bid of 100 that is
        // paid into the pot has a prior pot (the preimage amount) of 9900.
        Preimage pre = sim.preimageFor("bid",
            Preimage.builder().locktime(500_000).amount(BigInteger.valueOf(10000 - 100)).build(),
            SIG, ALICE, Bigint.of(100));
        sim.callStateful("bid", pre, SIG, ALICE, Bigint.of(100));
        assertEquals(ALICE, a.highestBidder);
        assertEquals(Bigint.of(100), a.highestBid);
    }

    @Test
    void bidRejectsNonIncreasingAmount() {
        Auction a = new Auction(AUCTIONEER, AUCTIONEER, Bigint.of(500), Bigint.of(1_000_000));
        ContractSimulator sim = ContractSimulator.stateful(a, SOURCE);
        // Paid (N-027), so the only failing assert is bidAmount > highestBid.
        Preimage pre = sim.preimageFor("bid",
            Preimage.builder().locktime(100_000).amount(BigInteger.valueOf(10000 - 400)).build(),
            SIG, BOB, Bigint.of(400));
        AssertionError e = assertThrows(
            AssertionError.class,
            () -> sim.callStateful("bid", pre, SIG, BOB, Bigint.of(400))
        );
        assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
            "rejected by bid's own rule, not by the preimage check");
    }

    /**
     * N-027: the bid must be paid into the pot. A pot of 10000 carried forward
     * unpaid (continuation 10000) passes F-024's {@code >= input} floor but not
     * bid's rule, and neither does a continuation one satoshi short.
     */
    @Test
    void bidRejectsUnpaidBid() {
        for (long pot : new long[] {10000, 10000 - 100 + 1}) {
            Auction a = new Auction(AUCTIONEER, AUCTIONEER, Bigint.ZERO, Bigint.of(1_000_000));
            ContractSimulator sim = ContractSimulator.stateful(a, SOURCE);
            Preimage pre = sim.preimageFor("bid",
                Preimage.builder().locktime(500_000).amount(BigInteger.valueOf(pot)).build(),
                SIG, ALICE, Bigint.of(100));
            AssertionError e = assertThrows(AssertionError.class,
                () -> sim.callStateful("bid", pre, SIG, ALICE, Bigint.of(100)),
                "bid with prior pot " + pot + " must be rejected");
            assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
                "rejected by bid's payment rule, not by the preimage check");
            assertEquals(Bigint.ZERO, a.highestBid);
        }
    }

    @Test
    void closeRequiresDeadlinePassed() {
        Auction a = new Auction(AUCTIONEER, ALICE, Bigint.of(100), Bigint.of(1_000_000));
        ContractSimulator sim = ContractSimulator.stateful(a, SOURCE);
        // Before deadline: fails.
        Preimage before = sim.preimageFor("close", Preimage.builder().locktime(500_000).build(), SIG);
        AssertionError e = assertThrows(AssertionError.class, () -> sim.callStateful("close", before, SIG));
        assertFalse(String.valueOf(e.getMessage()).startsWith("checkPreimage"),
            "rejected by close's deadline rule, not by the preimage check");
        // After deadline: succeeds.
        Preimage after = sim.preimageFor("close", Preimage.builder().locktime(2_000_000).build(), SIG);
        sim.callStateful("close", after, SIG);
    }
}
