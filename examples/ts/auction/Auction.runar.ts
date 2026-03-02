import { StatefulSmartContract, assert, checkSig, extractLocktime } from 'runar-lang';
import type { PubKey, Sig } from 'runar-lang';

class Auction extends StatefulSmartContract {
  readonly auctioneer: PubKey;
  highestBidder: PubKey;     // stateful
  highestBid: bigint;         // stateful
  readonly deadline: bigint;  // block height deadline

  constructor(auctioneer: PubKey, highestBidder: PubKey, highestBid: bigint, deadline: bigint) {
    super(auctioneer, highestBidder, highestBid, deadline);
    this.auctioneer = auctioneer;
    this.highestBidder = highestBidder;
    this.highestBid = highestBid;
    this.deadline = deadline;
  }

  // State-mutating: compiler auto-injects checkPreimage + state continuation
  public bid(bidder: PubKey, bidAmount: bigint) {
    // Bid must be higher than current highest
    assert(bidAmount > this.highestBid);

    // Auction must not have ended
    assert(extractLocktime(this.txPreimage) < this.deadline);

    // Update state
    this.highestBidder = bidder;
    this.highestBid = bidAmount;
  }

  // Non-mutating: compiler auto-injects checkPreimage only (no state continuation)
  public close(sig: Sig) {
    // Only auctioneer can close
    assert(checkSig(sig, this.auctioneer));

    // Auction must have ended
    assert(extractLocktime(this.txPreimage) >= this.deadline);
  }
}
