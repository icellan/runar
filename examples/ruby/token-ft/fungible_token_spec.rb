# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'FungibleTokenExample.runar'

RSpec.describe FungibleToken do
  it 'transfers tokens' do
    c = FungibleToken.new(mock_pub_key, 1000, 0, 'ab' * 16)
    recipient = '03' + '01' * 32
    c.transfer(mock_sig, recipient, 300, 546)
    expect(c.outputs.length).to eq(2)
  end

  it 'fails to transfer more than balance' do
    c = FungibleToken.new(mock_pub_key, 100, 0, 'ab' * 16)
    expect { c.transfer(mock_sig, mock_pub_key, 200, 546) }.to raise_error(RuntimeError)
  end

  it 'sends all tokens' do
    c = FungibleToken.new(mock_pub_key, 1000, 0, 'ab' * 16)
    recipient = '03' + '01' * 32
    c.send(mock_sig, recipient, 546)
    expect(c.outputs.length).to eq(1)
  end
end
