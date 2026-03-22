# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'P2PKH.runar'

RSpec.describe P2PKH do
  it 'unlocks with valid signature' do
    pk = mock_pub_key
    c = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, pk) }.not_to raise_error
  end

  it 'fails with wrong public key' do
    pk = mock_pub_key
    wrong_pk = '03' + '00' * 32
    c = P2PKH.new(hash160(pk))
    expect { c.unlock(mock_sig, wrong_pk) }.to raise_error(RuntimeError)
  end
end
