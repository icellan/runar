# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'BSV21Token.runar'

RSpec.describe BSV21Token do
  it 'unlocks with the matching public key' do
    pk = mock_pub_key
    c = BSV21Token.new(hash160(pk))
    expect { c.unlock(mock_sig, pk) }.not_to raise_error
  end

  it 'fails to unlock with a wrong public key' do
    pk = mock_pub_key
    wrong_pk = '03' + '00' * 32
    c = BSV21Token.new(hash160(pk))
    expect { c.unlock(mock_sig, wrong_pk) }.to raise_error(RuntimeError)
  end
end
