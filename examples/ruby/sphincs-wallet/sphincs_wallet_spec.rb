# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'SPHINCSWallet.runar'

RSpec.describe SPHINCSWallet do
  it 'spends with valid SLH-DSA signature' do
    c = SPHINCSWallet.new('00' * 32)
    # verify_slh_dsa_sha2_128s is mocked to return true
    expect { c.spend('00' * 5, '00' * 7856) }.not_to raise_error
  end
end
