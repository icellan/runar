import { SmartContract, assert, PubKey, Sig, SigHashPreimage, ByteString, checkSig, checkPreimage, hash256, extractOutputHash, extractLocktime } from 'tsop-lang';

class Auction extends SmartContract {
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

  public bid(bidder: PubKey, bidAmount: bigint, txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));

    // Bid must be higher than current highest
    assert(bidAmount > this.highestBid);

    // Auction must not have ended
    assert(extractLocktime(txPreimage) < this.deadline);

    // Update state
    this.highestBidder = bidder;
    this.highestBid = bidAmount;

    assert(hash256(this.getStateScript()) === extractOutputHash(txPreimage));
  }

  public close(sig: Sig, txPreimage: SigHashPreimage) {
    assert(checkPreimage(txPreimage));

    // Only auctioneer can close
    assert(checkSig(sig, this.auctioneer));

    // Auction must have ended
    assert(extractLocktime(txPreimage) >= this.deadline);

    // No state continuation - auction is done
  }
}
