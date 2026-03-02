pragma runar ^0.1.0;

contract Auction is StatefulSmartContract {
    PubKey immutable auctioneer;
    PubKey highestBidder;
    bigint highestBid;
    bigint immutable deadline;

    constructor(PubKey _auctioneer, PubKey _highestBidder, bigint _highestBid, bigint _deadline) {
        auctioneer = _auctioneer;
        highestBidder = _highestBidder;
        highestBid = _highestBid;
        deadline = _deadline;
    }

    // State-mutating: compiler auto-injects checkPreimage + state continuation
    function bid(PubKey bidder, bigint bidAmount) public {
        // Bid must be higher than current highest
        require(bidAmount > this.highestBid);

        // Auction must not have ended
        require(extractLocktime(this.txPreimage) < this.deadline);

        // Update state
        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    // Non-mutating: compiler auto-injects checkPreimage only (no state continuation)
    function close(Sig sig) public {
        // Only auctioneer can close
        require(checkSig(sig, this.auctioneer));

        // Auction must have ended
        require(extractLocktime(this.txPreimage) >= this.deadline);
    }
}
