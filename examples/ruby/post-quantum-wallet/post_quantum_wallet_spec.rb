# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'PostQuantumWallet.runar'

RSpec.describe PostQuantumWallet do
  it 'spends with valid WOTS+ signature' do
    c = PostQuantumWallet.new('00' * 32)
    # verify_wots is mocked to return true
    expect { c.spend('00' * 5, '00' * 2144) }.not_to raise_error
  end
end
