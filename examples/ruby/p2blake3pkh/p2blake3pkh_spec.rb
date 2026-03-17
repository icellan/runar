# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'P2Blake3PKH.runar'

RSpec.describe P2Blake3PKH do
  # blake3_hash is mocked -- always returns 32 zero bytes as hex.
  # Construct contracts with pub_key_hash = '00' * 32 so the hash check passes.
  let(:alice)          { Runar::TestKeys::ALICE }
  let(:pk)             { alice.pub_key }
  let(:sig)            { alice.test_sig }
  let(:mock_hash)      { blake3_hash(pk) }  # '00' * 32 in test mode

  describe '#unlock' do
    it 'unlocks with a valid signature when pub_key_hash matches mock blake3_hash' do
      c = P2Blake3PKH.new(mock_hash)
      expect { c.unlock(sig, pk) }.not_to raise_error
    end

    it 'fails when pub_key_hash does not match mock blake3_hash' do
      wrong_hash = 'ff' * 32
      c = P2Blake3PKH.new(wrong_hash)
      expect { c.unlock(sig, pk) }.to raise_error(RuntimeError)
    end

    it 'fails with wrong public key (signature mismatch)' do
      bob = Runar::TestKeys::BOB
      # Use BOB's pub_key but ALICE's sig -- check_sig will fail
      c = P2Blake3PKH.new(mock_hash)
      expect { c.unlock(sig, bob.pub_key) }.to raise_error(RuntimeError)
    end
  end
end
