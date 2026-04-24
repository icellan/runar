package runar.examples.auction;

import runar.lang.StatefulSmartContract;
import runar.lang.annotations.Public;
import runar.lang.annotations.Readonly;
import runar.lang.types.Bigint;
import runar.lang.types.PubKey;
import runar.lang.types.Sig;

import static runar.lang.Builtins.assertThat;
import static runar.lang.Builtins.checkSig;
import static runar.lang.Builtins.extractLocktime;

/**
 * Auction -- on-chain English auction.
 *
 * <p>Ports {@code examples/go/auction/Auction.runar.go} to Java.
 * Bidders compete by submitting progressively higher bids until a
 * block-height deadline. After the deadline, only the auctioneer can
 * close the auction.
 *
 * <p>Time enforcement is via {@code extractLocktime(this.txPreimage)}.
 * Inside the simulator, {@link runar.lang.Builtins#extractLocktime}
 * returns {@code 0}, so tests that exercise the deadline path must
 * construct a {@link runar.lang.runtime.Preimage} with an explicit
 * {@code locktime(...)} and call via
 * {@link runar.lang.runtime.ContractSimulator#callStateful}.
 */
class Auction extends StatefulSmartContract {

    @Readonly PubKey auctioneer;
    PubKey highestBidder;
    Bigint highestBid;
    @Readonly Bigint deadline;

    Auction(PubKey auctioneer, PubKey highestBidder, Bigint highestBid, Bigint deadline) {
        super(auctioneer, highestBidder, highestBid, deadline);
        this.auctioneer = auctioneer;
        this.highestBidder = highestBidder;
        this.highestBid = highestBid;
        this.deadline = deadline;
    }

    /** Submit a new bid that outbids the current highest. */
    @Public
    void bid(Sig sig, PubKey bidder, Bigint bidAmount) {
        assertThat(checkSig(sig, bidder));
        assertThat(bidAmount.gt(this.highestBid));
        // The auction is still open: nLockTime < deadline.
        assertThat(Bigint.of(extractLocktime(this.txPreimage)).lt(this.deadline));
        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    /** Finalise the auction after the deadline has passed. */
    @Public
    void close(Sig sig) {
        assertThat(checkSig(sig, this.auctioneer));
        assertThat(Bigint.of(extractLocktime(this.txPreimage)).ge(this.deadline));
    }
}
