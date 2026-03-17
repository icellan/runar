# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Blake3Test.runar'

RSpec.describe Blake3Test do
  # Mock blake3_compress and blake3_hash both return 32 zero bytes (hex).
  # Set expected to the same value so assertions pass.
  let(:zero_hash) { '00' * 32 }

  describe '#verify_compress' do
    it 'passes when result matches expected' do
      c = Blake3Test.new(zero_hash)
      expect { c.verify_compress('00' * 32, '00' * 64) }.not_to raise_error
    end

    it 'fails when expected does not match mock result' do
      wrong_expected = 'ff' * 32
      c = Blake3Test.new(wrong_expected)
      expect { c.verify_compress('00' * 32, '00' * 64) }.to raise_error(RuntimeError)
    end
  end

  describe '#verify_hash' do
    it 'passes when result matches expected' do
      c = Blake3Test.new(zero_hash)
      expect { c.verify_hash('00' * 32) }.not_to raise_error
    end

    it 'fails when expected does not match mock result' do
      wrong_expected = 'ff' * 32
      c = Blake3Test.new(wrong_expected)
      expect { c.verify_hash('00' * 32) }.to raise_error(RuntimeError)
    end

    it 'accepts any message -- mock always returns zero hash' do
      c = Blake3Test.new(zero_hash)
      expect { c.verify_hash('deadbeef') }.not_to raise_error
    end
  end
end
