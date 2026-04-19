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
      '7669004d96866a6330a609d9ad1a08a4f8507c4d04eefd1a50f00b02556aab86'
    )
  end

  it 'hashes "abc" (hex-encoded) to a known value' do
    expect(blake3_hash('616263')).to eq(
      '6f9871b5d6e80fc882e7bb57857f8b279cdc229664eab9382d2838dbf7d8a20d'
    )
  end

  it 'hashes "hello world" (hex-encoded) to a known value' do
    expect(blake3_hash('68656c6c6f20776f726c64')).to eq(
      '47d3d7048c7ed47c986773cc1eefaa0b356bec676dd62cca3269a086999d65fc'
    )
  end

  it 'agrees with blake3_compress(IV, zero-pad(msg, 64)) — hash wraps compress' do
    msg = 'abc'
    padded = ([msg].pack('H*') + "\x00".b * (64 - 'abc'.bytesize / 2)).byteslice(0, 64)
    direct = Runar::Builtins._blake3_compress_impl(
      Runar::Builtins::BLAKE3_IV_BYTES, padded
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
