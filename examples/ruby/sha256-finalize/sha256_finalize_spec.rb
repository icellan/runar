# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'Sha256Finalize.runar'

# SHA-256 IV: first 32 bits of the fractional parts of the square roots of
# the first 8 primes (FIPS 180-4 Section 5.3.3).
SHA256_IV_FINALIZE = '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19'

# SHA-256("abc") digest (verified against Ruby Digest::SHA256 and Python hashlib).
ABC_DIGEST_FINALIZE = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

RSpec.describe Sha256Finalize do
  let(:abc_hex) { '616263' } # "abc" as hex
  let(:abc_bits) { 24 }      # 3 bytes * 8

  it 'produces SHA-256("abc") via finalize-only path' do
    # "abc" is 3 bytes (24 bits), fits in single-block finalize path.
    c = Sha256Finalize.new(ABC_DIGEST_FINALIZE)
    expect { c.verify(SHA256_IV_FINALIZE, abc_hex, abc_bits) }.not_to raise_error
  end

  it 'fails when expected does not match the finalize result' do
    wrong_expected = 'ff' * 32
    c = Sha256Finalize.new(wrong_expected)
    expect { c.verify(SHA256_IV_FINALIZE, abc_hex, abc_bits) }.to raise_error(RuntimeError)
  end

  it 'passes when expected is computed dynamically from sha256_finalize' do
    expected = sha256_finalize(SHA256_IV_FINALIZE, abc_hex, abc_bits)
    c = Sha256Finalize.new(expected)
    expect { c.verify(SHA256_IV_FINALIZE, abc_hex, abc_bits) }.not_to raise_error
  end

  it 'handles an empty remaining message (msg_bit_len = 0)' do
    # sha256_finalize(IV, "", 0) equals SHA-256 of the empty string.
    expected_empty_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    c = Sha256Finalize.new(expected_empty_sha256)
    expect { c.verify(SHA256_IV_FINALIZE, '', 0) }.not_to raise_error
  end

  it 'handles a 55-byte message (boundary of single-block path)' do
    # 55 bytes: the maximum that fits in a single finalize block.
    msg_hex = 'aa' * 55
    msg_bits = 55 * 8
    expected = sha256_finalize(SHA256_IV_FINALIZE, msg_hex, msg_bits)
    c = Sha256Finalize.new(expected)
    expect { c.verify(SHA256_IV_FINALIZE, msg_hex, msg_bits) }.not_to raise_error
  end

  it 'handles a 56-byte message (two-block path)' do
    # 56 bytes triggers the two-block padding path.
    msg_hex = 'bb' * 56
    msg_bits = 56 * 8
    expected = sha256_finalize(SHA256_IV_FINALIZE, msg_hex, msg_bits)
    c = Sha256Finalize.new(expected)
    expect { c.verify(SHA256_IV_FINALIZE, msg_hex, msg_bits) }.not_to raise_error
  end
end
