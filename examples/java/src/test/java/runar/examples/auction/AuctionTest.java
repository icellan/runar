package runar.examples.auction;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;
import runar.lang.runtime.ContractSimulator;
import runar.lang.runtime.Preimage;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuctionTest {

    private static final PubKey AUCTIONEER = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000001");
    private static final PubKey ALICE      = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000002");
    private static final PubKey BOB        = PubKey.fromHex("020000000000000000000000000000000000000000000000000000000000000003");
    private static final Sig SIG = Sig.fromHex("30440220" + "00".repeat(32) + "0220" + "00".repeat(32));

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
        ContractSimulator sim = ContractSimulator.stateful(a);
        Preimage pre = Preimage.builder().locktime(500_000).build();
        sim.callStateful("bid", pre, SIG, ALICE, Bigint.of(100));
        assertEquals(ALICE, a.highestBidder);
        assertEquals(Bigint.of(100), a.highestBid);
    }

    @Test
    void bidRejectsNonIncreasingAmount() {
        Auction a = new Auction(AUCTIONEER, AUCTIONEER, Bigint.of(500), Bigint.of(1_000_000));
        ContractSimulator sim = ContractSimulator.stateful(a);
        Preimage pre = Preimage.builder().locktime(100_000).build();
        assertThrows(
            AssertionError.class,
            () -> sim.callStateful("bid", pre, SIG, BOB, Bigint.of(400))
        );
    }

    @Test
    void closeRequiresDeadlinePassed() {
        Auction a = new Auction(AUCTIONEER, ALICE, Bigint.of(100), Bigint.of(1_000_000));
        ContractSimulator sim = ContractSimulator.stateful(a);
        // Before deadline: fails.
        Preimage before = Preimage.builder().locktime(500_000).build();
        assertThrows(AssertionError.class, () -> sim.callStateful("close", before, SIG));
        // After deadline: succeeds.
        Preimage after = Preimage.builder().locktime(2_000_000).build();
        sim.callStateful("close", after, SIG);
    }
}
