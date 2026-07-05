# frozen_string_literal: true

# BLAKE3 runtime — real single-block implementation.
#
# Before the fix, `blake3_compress` / `blake3_hash` returned 32 zero bytes
# (hex-encoded). Contract-level tests that exercised BLAKE3 were silently
# running against a placeholder. This spec pins byte-identical output
# against the TS interpreter and Python runtime so any regression is caught.

require 'spec_helper'
require 'runar/builtins'

RSpec.describe 'Runar::Builtins BLAKE3' do
  include Runar::Builtins

  it 'hashes the empty string to a known value' do
    expect(blake3_hash('')).to eq(
      'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'
    )
  end

  it 'hashes "abc" (hex-encoded) to a known value' do
    expect(blake3_hash('616263')).to eq(
      '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85'
    )
  end

  it 'hashes "hello world" (hex-encoded) to a known value' do
    expect(blake3_hash('68656c6c6f20776f726c64')).to eq(
      'd74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24'
    )
  end

  it 'agrees with blake3_compress(IV, zero-pad(msg, 64)) — hash wraps compress' do
    msg = 'abc'
    msg_bytes = [msg].pack('H*')
    padded = (msg_bytes + "\x00".b * 64).byteslice(0, 64)
    # blake3_hash uses the real message length as block_len (v[14]); the direct
    # compress call must supply the same length for the invariant to hold.
    direct = Runar::Builtins._blake3_compress_impl(
      Runar::Builtins::BLAKE3_IV_BYTES, padded, msg_bytes.bytesize
    ).unpack1('H*')
    expect(blake3_hash(msg)).to eq(direct)
  end

  it 'is deterministic across invocations' do
    cv    = '00' * 32
    block = 'ff' * 64
    expect(blake3_compress(cv, block)).to eq(blake3_compress(cv, block))
  end

  it 'does NOT return the legacy 32-zero-byte stub' do
    expect(blake3_compress('00' * 32, '00' * 64)).not_to eq('00' * 32)
  end
end
