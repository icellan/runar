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

    function bid(Sig sig, PubKey bidder, bigint bidAmount) public {
        require(checkSig(sig, bidder));
        require(bidAmount > this.highestBid);
        require(extractLocktime(this.txPreimage) < this.deadline);
        this.highestBidder = bidder;
        this.highestBid = bidAmount;
    }

    function close(Sig sig) public {
        require(checkSig(sig, this.auctioneer));
        require(extractLocktime(this.txPreimage) >= this.deadline);
    }
}
