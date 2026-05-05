# frozen_string_literal: true

# Runtime vectors -- cross-SDK consistency check.
#
# Loads `conformance/runtime-vectors/hashes.json` (the cross-SDK source of
# truth for `sha256Finalize`, `blake3Compress`, and `blake3Hash` outputs)
# and asserts that the Ruby SDK's runtime helpers in `Runar::Builtins`
# produce the documented output byte-for-byte. Every other consumer
# (TS / Java / Python / Go / Rust / Zig) loads the same file and runs the
# equivalent assertion; a divergence between any two runtime impls shows
# up here.
#
# Reference: `_consumers` in the JSON file enumerates the per-SDK tests
# that share these vectors.

require 'json'
require 'pathname'
require 'spec_helper'
require 'runar/builtins'

def find_runtime_vectors
  here = Pathname.new(__FILE__).realpath
  here.ascend do |dir|
    candidate = dir.join('conformance', 'runtime-vectors', 'hashes.json')
    return candidate if candidate.file?
  end
  raise "could not locate conformance/runtime-vectors/hashes.json walking up from #{__FILE__}"
end

VECTORS_PATH = find_runtime_vectors
VECTORS = JSON.parse(VECTORS_PATH.read).freeze

RSpec.describe 'Runtime vectors' do
  include Runar::Builtins

  describe 'sha256_finalize' do
    VECTORS['sha256_finalize'].each do |v|
      it v['name'] do
        expect(sha256_finalize(v['state'], v['remaining'], v['msg_bit_len']))
          .to eq(v['expected'])
      end
    end
  end

  describe 'blake3_compress' do
    VECTORS['blake3_compress'].each do |v|
      it v['name'] do
        expect(blake3_compress(v['state'], v['block'])).to eq(v['expected'])
      end
    end
  end

  describe 'blake3_hash' do
    VECTORS['blake3_hash'].each do |v|
      it v['name'] do
        expect(blake3_hash(v['input'])).to eq(v['expected'])
      end
    end
  end

  describe 'constants' do
    it 'blake3_iv == sha256_iv (BLAKE3 spec — both reuse the SHA-256 IV)' do
      expect(VECTORS['constants']['blake3_iv']).to eq(VECTORS['constants']['sha256_iv'])
    end

    it 'blake3_compress(IV, zeros) yields 32-byte output' do
      cv = VECTORS['constants']['blake3_iv']
      zeros = '00' * 64
      got = blake3_compress(cv, zeros)
      expect(got.length).to eq(64) # 32 bytes hex-encoded
    end
  end
end
