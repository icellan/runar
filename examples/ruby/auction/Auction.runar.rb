require 'runar'

# On-chain English auction.
#
# Time enforcement — read this before copying the pattern. nLockTime is chosen
# by the SPENDER and enforced by consensus as a NOT-BEFORE: the transaction
# becomes mineable once the chain has reached it. Nothing about it bounds the
# chain from above. A script can therefore assert "not before T" and can NEVER
# assert "before T" — a bidder at height T+1 simply stamps a stale nLockTime of
# T-1 and the node mines it.
#
# So bid carries no deadline check at all: bidding is open until the auctioneer
# closes. close uses the direction that does work, nLockTime >= deadline, paired
# with extract_sequence != 0xffffffff. That second assert is load-bearing, not
# decoration: consensus ignores nLockTime entirely when every input is final, so
# without it the auctioneer could stamp nLockTime = deadline on an all-final
# transaction and close at any height, before anyone had a chance to bid.
#
# A trustless "bids only before T" window needs a time source the contract can
# read as state — an oracle or a tick — not the spending transaction's own
# locktime. v1 does not ship one.

class Auction < Runar::StatefulSmartContract
  prop :auctioneer, PubKey, readonly: true
  prop :highest_bidder, PubKey
  prop :highest_bid, Bigint
  prop :deadline, Bigint, readonly: true

  def initialize(auctioneer, highest_bidder, highest_bid, deadline)
    super(auctioneer, highest_bidder, highest_bid, deadline)
    @auctioneer = auctioneer
    @highest_bidder = highest_bidder
    @highest_bid = highest_bid
    @deadline = deadline
  end

  runar_public sig: Sig, bidder: PubKey, bid_amount: Bigint
  def bid(sig, bidder, bid_amount)
    assert check_sig(sig, bidder)
    assert bid_amount > @highest_bid
    @highest_bidder = bidder
    @highest_bid = bid_amount
  end

  runar_public sig: Sig
  def close(sig)
    assert check_sig(sig, @auctioneer)
    assert extract_locktime(@tx_preimage) >= @deadline
    # ...and that consensus actually enforces that nLockTime. A transaction
    # whose inputs are all final (nSequence 0xffffffff) is mineable at any height
    # with nLockTime ignored, so without this the assert above is script-only
    # theatre and the auctioneer can close immediately.
    assert extract_sequence(@tx_preimage) != 4294967295
  end
end
