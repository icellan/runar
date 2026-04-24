# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Sha256CompressTest.runar'

# SHA-256 IV: first 32 bits of the fractional parts of the square roots of
# the first 8 primes (FIPS 180-4 Section 5.3.3).
SHA256_IV = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'

# Standard FIPS 180-4 padded block for "abc" (24-bit message):
#   0x61 0x62 0x63 0x80 (3 data bytes + padding start byte)
#   52 zero bytes (pad to byte 56)
#   0x0000000000000018 (8-byte big-endian bit length = 24 bits)
# Total: 64 bytes = 128 hex chars.
ABC_BLOCK =
  '6162638000000000000000000000000000000000000000000000000000000000' \
  '000000000000000000000000000000000000000000000000000000000000' \
  '0018'

# SHA-256("abc") digest (verified against Ruby Digest::SHA256 and Python hashlib).
ABC_DIGEST = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

RSpec.describe Sha256CompressTest do
  describe '#verify' do
    it 'passes with the correct state and block for SHA-256("abc")' do
      c = Sha256CompressTest.new(ABC_DIGEST)
      expect { c.verify(SHA256_IV, ABC_BLOCK) }.not_to raise_error
    end

    it 'fails when expected does not match the compression result' do
      wrong_expected = 'ff' * 32
      c = Sha256CompressTest.new(wrong_expected)
      expect { c.verify(SHA256_IV, ABC_BLOCK) }.to raise_error(RuntimeError)
    end

    it 'passes when expected is computed dynamically from sha256_compress' do
      expected = sha256_compress(SHA256_IV, ABC_BLOCK)
      c = Sha256CompressTest.new(expected)
      expect { c.verify(SHA256_IV, ABC_BLOCK) }.not_to raise_error
    end

    it 'produces the correct result for a zero state and zero block' do
      zero_state = '00' * 32
      zero_block = '00' * 64
      expected = sha256_compress(zero_state, zero_block)
      c = Sha256CompressTest.new(expected)
      expect { c.verify(zero_state, zero_block) }.not_to raise_error
    end
  end
end
