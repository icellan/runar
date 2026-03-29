import { StatefulSmartContract, assert, checkSig, extractLocktime } from 'runar-lang';

class Auction extends StatefulSmartContract {
  readonly auctioneer: PubKey;
  highestBidder: PubKey;
  highestBid: bigint;
  readonly deadline: bigint;

  constructor(auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint) {
    super(auctioneer, highestBidder, highestBid, deadline);
    this.auctioneer = auctioneer;
    this.highestBidder = highestBidder;
    this.highestBid = highestBid;
    this.deadline = deadline;
  }

  public bid(sig: Sig, bidder: PubKey, bidAmount: bigint) {
    assert(checkSig(sig, bidder));
    assert(bidAmount > this.highestBid);
    assert(extractLocktime(this.txPreimage) < this.deadline);
    this.highestBidder = bidder;
    this.highestBid = bidAmount;
  }

  public close(sig: Sig) {
    assert(checkSig(sig, this.auctioneer));
    assert(extractLocktime(this.txPreimage) >= this.deadline);
  }
}
