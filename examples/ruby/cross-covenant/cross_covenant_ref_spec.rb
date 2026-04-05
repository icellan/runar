# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'CrossCovenantRef.runar'
require 'digest'

def hash256_for_test(hex)
  first = Digest::SHA256.hexdigest([hex].pack('H*'))
  Digest::SHA256.hexdigest([first].pack('H*'))
end

RSpec.describe CrossCovenantRef do
  # Simulate a referenced output: some bytes with an embedded state root
  # Layout: 16 bytes prefix + 32 bytes state root + 8 bytes suffix
  let(:prefix) { 'aabbccddee0011223344556677889900' }
  let(:state_root) { 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }
  let(:suffix) { '0102030405060708' }
  let(:referenced_output) { prefix + state_root + suffix }

  # Hash of the referenced output
  let(:output_hash) { hash256_for_test(referenced_output) }

  describe 'verify_and_extract' do
    it 'accepts valid output with correct state root' do
      c = CrossCovenantRef.new(output_hash)
      expect { c.verify_and_extract(referenced_output, state_root, 16) }.not_to raise_error
    end

    it 'rejects tampered output (wrong hash)' do
      c = CrossCovenantRef.new(output_hash)
      tampered = 'ff' + referenced_output[2..]
      expect { c.verify_and_extract(tampered, state_root, 16) }.to raise_error(RuntimeError)
    end

    it 'rejects wrong state root expectation' do
      c = CrossCovenantRef.new(output_hash)
      wrong_root = '0000000000000000000000000000000000000000000000000000000000000000'
      expect { c.verify_and_extract(referenced_output, wrong_root, 16) }.to raise_error(RuntimeError)
    end
  end
end
