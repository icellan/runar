require 'runar'

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
    assert extract_locktime(@tx_preimage) < @deadline
    @highest_bidder = bidder
    @highest_bid = bid_amount
  end

  runar_public sig: Sig
  def close(sig)
    assert check_sig(sig, @auctioneer)
    assert extract_locktime(@tx_preimage) >= @deadline
  end
end
