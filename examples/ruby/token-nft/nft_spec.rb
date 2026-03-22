# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'NFTExample.runar'

RSpec.describe SimpleNFT do
  it 'transfers ownership' do
    c = SimpleNFT.new(mock_pub_key, '01' * 16, '02' * 32)
    new_owner = '03' + '01' * 32
    c.transfer(mock_sig, new_owner, 546)
    expect(c.outputs.length).to eq(1)
  end

  it 'burns the token' do
    c = SimpleNFT.new(mock_pub_key, '01' * 16, '02' * 32)
    c.burn(mock_sig)
    expect(c.outputs.length).to eq(0)
  end
end
