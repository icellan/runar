# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Blake3Test.runar'

RSpec.describe Blake3Test do
  include Runar::Builtins

  describe '#verify_compress' do
    it 'passes when expected matches the real BLAKE3 output' do
      cv    = '00' * 32
      block = '00' * 64
      c = Blake3Test.new(blake3_compress(cv, block))
      expect { c.verify_compress(cv, block) }.not_to raise_error
    end

    it 'fails when expected does not match the real output' do
      c = Blake3Test.new('ff' * 32)
      expect { c.verify_compress('00' * 32, '00' * 64) }.to raise_error(RuntimeError)
    end
  end

  describe '#verify_hash' do
    it 'passes for empty input with the pinned reference hash' do
      c = Blake3Test.new('7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86')
      expect { c.verify_hash('') }.not_to raise_error
    end

    it 'fails when expected does not match the real hash' do
      c = Blake3Test.new('ff' * 32)
      expect { c.verify_hash('00' * 32) }.to raise_error(RuntimeError)
    end

    it 'accepts arbitrary input when expected is recomputed from the runtime' do
      msg = 'deadbeef'
      c = Blake3Test.new(blake3_hash(msg))
      expect { c.verify_hash(msg) }.not_to raise_error
    end
  end
end
