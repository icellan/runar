# frozen_string_literal: true

require 'spec_helper'
require 'digest'

# GK-BUG-013 (off-chain half, Ruby tier): sha256_finalize must refuse a
# msgBitLen outside [0, 2^64), the domain the compiled script enforces with its
# `<00> OP_EQUALVERIFY` sign-byte check. It used to hand the value to
# `[msg_bit_len].pack('Q>')`, which silently wraps a negative to 2^64 - |n|
# (a digest no script computes) and raises an unrelated RangeError from 2^64 up.
#
# Proves: -24, -1, 2^64 and 2^64 + 24 raise ArgumentError naming the domain and
# the value; 24 still yields Digest::SHA256('abc'); 2^64 - 8 (the top of the
# domain) is accepted and equals a one-block FIPS 180-4 reference anchored to
# Digest::SHA256.
# Does not prove: the other six tiers (each has its own gk-bug-013 test).
RSpec.describe 'GK-BUG-013 sha256_finalize msgBitLen domain' do
  let(:ctx) { Object.new.extend(Runar::Builtins) }
  let(:iv) { '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19' }
  let(:abc) { 'abc'.unpack1('H*') }

  def ref_one_block(ctx, iv, tail_hex, length_field)
    block = ([tail_hex].pack('H*') + "\x80".b).ljust(56, "\x00".b) + [length_field].pack('Q>')
    ctx.sha256_compress(iv, block.unpack1('H*'))
  end

  it 'the reference is anchored to Digest::SHA256' do
    expect(ref_one_block(ctx, iv, abc, 24)).to eq(Digest::SHA256.hexdigest('abc'))
  end

  it '24 still computes SHA-256("abc")' do
    expect(ctx.sha256_finalize(iv, abc, 24)).to eq(Digest::SHA256.hexdigest('abc'))
  end

  [-24, -1, 1 << 64, (1 << 64) + 24].each do |bit_len|
    it "refuses #{bit_len} with the msgBitLen domain diagnostic" do
      expect { ctx.sha256_finalize(iv, abc, bit_len) }
        .to raise_error(ArgumentError, /sha256Finalize: msgBitLen must be in \[0, 2\^64\), got #{Regexp.escape(bit_len.to_s)}\b/)
    end
  end

  it 'accepts the top of the domain' do
    top = (1 << 64) - 8
    expect(ctx.sha256_finalize(iv, abc, top)).to eq(ref_one_block(ctx, iv, abc, top))
  end
end
