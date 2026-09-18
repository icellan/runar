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
import static runar.lang.Builtins.extractSequence;

/**
 * Auction -- on-chain English auction.
 *
 * <p>Ports {@code examples/go/auction/Auction.runar.go} to Java.
 * Bidders compete by submitting progressively higher bids until a
 * block-height deadline. After the deadline, only the auctioneer can
 * close the auction.
 *
 * <p><b>Time enforcement — read this before copying the pattern.</b>
 * {@code nLockTime} is chosen by the <i>spender</i> and enforced by
 * consensus as a NOT-BEFORE: the transaction becomes mineable once the
 * chain has reached it. Nothing about it bounds the chain from above. A
 * script can therefore assert "not before T" and can NEVER assert
 * "before T" — a bidder at height T+1 simply stamps a stale
 * {@code nLockTime} of T-1 and the node mines it.
 *
 * <p>So {@link #bid} carries no deadline check at all: bidding is open
 * until the auctioneer closes. {@link #close} uses the direction that
 * does work, {@code nLockTime >= deadline}, paired with
 * {@code extractSequence != 0xffffffff}. That second assert is
 * load-bearing, not decoration: consensus ignores {@code nLockTime}
 * entirely when every input is final, so without it the auctioneer could
 * stamp {@code nLockTime = deadline} on an all-final transaction and
 * close at any height, before anyone had a chance to bid.
 *
 * <p>A trustless "bids only before T" window needs a time source the
 * contract can read as state — an oracle or a tick — not the spending
 * transaction's own locktime. v1 does not ship one.
 *
 * <p>Inside the simulator, {@link runar.lang.Builtins#extractLocktime}
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

    /**
     * Submit a new bid that outbids the current highest.
     *
     * <p>There is deliberately no deadline check here — see the class-level
     * Time enforcement note. A bid lands whenever the contract's UTXO is
     * still unspent.
     */
    @Public
    void bid(Sig sig, PubKey bidder, Bigint bidAmount) {
        assertThat(checkSig(sig, bidder));
        assertThat(bidAmount.gt(this.highestBid));
        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    /** Finalise the auction after the deadline has passed. */
    @Public
    void close(Sig sig) {
        assertThat(checkSig(sig, this.auctioneer));
        assertThat(Bigint.of(extractLocktime(this.txPreimage)).ge(this.deadline));
        // ...and that consensus actually enforces that nLockTime. A transaction
        // whose inputs are all final (nSequence 0xffffffff) is mineable at any
        // height with nLockTime ignored, so without this the assert above is
        // script-only theatre and the auctioneer can close immediately.
        assertThat(Bigint.of(extractSequence(this.txPreimage)).neq(Bigint.of(4294967295L)));
    }
}
