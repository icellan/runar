# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'MerkleProofDemo.runar'
require 'digest'

# ---------------------------------------------------------------------------
# Merkle tree helpers (for building test fixtures)
# ---------------------------------------------------------------------------

def sha256_hex(hex)
  Digest::SHA256.hexdigest([hex].pack('H*'))
end

def hash256_hex(hex)
  sha256_hex(sha256_hex(hex))
end

def build_merkle_tree(leaves, hash_fn)
  level = leaves.dup
  layers = [level]

  while level.length > 1
    nxt = []
    (0...level.length).step(2) do |i|
      nxt << hash_fn.call(level[i] + level[i + 1])
    end
    level = nxt
    layers << level
  end

  root = level[0]

  get_proof = lambda do |index|
    siblings = []
    idx = index
    (0...(layers.length - 1)).each do |d|
      sibling_idx = idx ^ 1
      siblings << layers[d][sibling_idx]
      idx = idx >> 1
    end
    { proof: siblings.join, leaf: leaves[index] }
  end

  { root: root, get_proof: get_proof }
end

RSpec.describe MerkleProofDemo do
  # Create 16 leaves (32-byte hashes)
  let(:leaves) do
    (0...16).map { |i| sha256_hex(format('%02x', i)) }
  end

  describe 'verify_sha256 (merkle_root_sha256, depth=4)' do
    let(:tree) { build_merkle_tree(leaves, method(:sha256_hex)) }

    it 'verifies leaf at index 0' do
      data = tree[:get_proof].call(0)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_sha256(data[:leaf], data[:proof], 0) }.not_to raise_error
    end

    it 'verifies leaf at index 7' do
      data = tree[:get_proof].call(7)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_sha256(data[:leaf], data[:proof], 7) }.not_to raise_error
    end

    it 'verifies leaf at index 15' do
      data = tree[:get_proof].call(15)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_sha256(data[:leaf], data[:proof], 15) }.not_to raise_error
    end

    it 'rejects wrong leaf' do
      data = tree[:get_proof].call(0)
      wrong_leaf = sha256_hex('ff')
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_sha256(wrong_leaf, data[:proof], 0) }.to raise_error(RuntimeError)
    end

    it 'rejects wrong index' do
      data = tree[:get_proof].call(0)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_sha256(data[:leaf], data[:proof], 1) }.to raise_error(RuntimeError)
    end
  end

  describe 'verify_hash256 (merkle_root_hash256, depth=4)' do
    let(:tree) { build_merkle_tree(leaves, method(:hash256_hex)) }

    it 'verifies leaf at index 0' do
      data = tree[:get_proof].call(0)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_hash256(data[:leaf], data[:proof], 0) }.not_to raise_error
    end

    it 'verifies leaf at index 10' do
      data = tree[:get_proof].call(10)
      c = MerkleProofDemo.new(tree[:root])
      expect { c.verify_hash256(data[:leaf], data[:proof], 10) }.not_to raise_error
    end
  end
end
