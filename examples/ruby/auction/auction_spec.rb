# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Auction.runar'

RSpec.describe Auction do
  it 'accepts a higher bid' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 1000)
    new_bidder = mock_pub_key
    c.bid(mock_sig, new_bidder, 200)
    expect(c.highest_bidder).to eq(new_bidder)
    expect(c.highest_bid).to eq(200)
  end

  it 'rejects a lower bid' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 1000)
    expect { c.bid(mock_sig, mock_pub_key, 50) }.to raise_error(RuntimeError)
  end

  it 'closes the auction' do
    c = Auction.new(mock_pub_key, mock_pub_key, 100, 0)
    expect { c.close(mock_sig) }.not_to raise_error
  end
end
