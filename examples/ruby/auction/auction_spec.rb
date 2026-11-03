# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Auction.runar'

# Bid with the continuation carrying the prior pot (extract_amount is 10_000
# off-chain) plus the bid (N-027).
def bid_paying(contract, sig, bidder, amount)
  prev = Runar::Builtins.mock_continuation_amount
  Runar::Builtins.mock_continuation_amount = 10_000 + amount
  contract.bid(sig, bidder, amount)
ensure
  Runar::Builtins.mock_continuation_amount = prev
end

RSpec.describe Auction do
  it 'accepts a higher bid' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 1000)
    new_bidder = mock_pub_key
    bid_paying(c, mock_sig, new_bidder, 200)
    expect(c.highest_bidder).to eq(new_bidder)
    expect(c.highest_bid).to eq(200)
  end

  it 'rejects a lower bid' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 1000)
    expect { bid_paying(c, mock_sig, mock_pub_key, 50) }.to raise_error(RuntimeError)
  end

  # N-027: the bid must be paid into the pot. Carrying the pot forward unpaid
  # (10_000) passes F-024's `>= input` floor but not bid's rule.
  [10_000, 10_000 + 200 - 1].each do |amount|
    it "rejects a bid whose continuation is #{amount}" do
      c = Auction.new(mock_pub_key, mock_pub_key, 100, 1000)
      prev = Runar::Builtins.mock_continuation_amount
      Runar::Builtins.mock_continuation_amount = amount
      begin
        expect { c.bid(mock_sig, mock_pub_key, 200) }.to raise_error(RuntimeError)
      ensure
        Runar::Builtins.mock_continuation_amount = prev
      end
      expect(c.highest_bid).to eq(100)
    end
  end

  it 'closes the auction' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 0)
    expect { c.close(mock_sig) }.not_to raise_error
  end
end
