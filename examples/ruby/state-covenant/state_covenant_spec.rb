# frozen_string_literal: true

require_relative '../spec_helper'
require_relative 'StateCovenant.runar'
require 'digest'

# Baby Bear field prime: p = 2^31 - 2^27 + 1 = 2013265921
BB_P = 2013265921

def bb_field_mul_helper(a, b)
  (a * b) % BB_P
end

def sha256_hex(hex_str)
  Digest::SHA256.hexdigest([hex_str].pack('H*'))
end

def hash256_hex(hex_str)
  sha256_hex(sha256_hex(hex_str))
end

def make_state_root(n)
  sha256_hex(format('%02x', n))
end

def build_sha256_merkle_tree(leaves)
  level = leaves.dup
  layers = [level.dup]
  while level.length > 1
    next_level = []
    (0...level.length).step(2) do |i|
      next_level << sha256_hex(level[i] + level[i + 1])
    end
    level = next_level
    layers << level.dup
  end
  [level[0], layers]
end

def get_proof(layers, index, leaves)
  siblings = []
  idx = index
  (0...(layers.length - 1)).each do |d|
    siblings << layers[d][idx ^ 1]
    idx >>= 1
  end
  [siblings.join, leaves[index]]
end

MERKLE_LEAVES = (0...16).map { |i| sha256_hex(format('%02x', i)) }
MERKLE_ROOT, MERKLE_LAYERS = build_sha256_merkle_tree(MERKLE_LEAVES)
VERIFYING_KEY_HASH = MERKLE_ROOT
LEAF_INDEX = 3
GENESIS_STATE_ROOT = '00' * 32

def build_advance_args(pre_state_root, new_block_number)
  new_state_root = make_state_root(new_block_number)
  batch_data_hash = hash256_hex(pre_state_root + new_state_root)
  proof_field_a = 1_000_000
  proof_field_b = 2_000_000
  proof_field_c = bb_field_mul_helper(proof_field_a, proof_field_b)
  proof, leaf = get_proof(MERKLE_LAYERS, LEAF_INDEX, MERKLE_LEAVES)
  {
    new_state_root: new_state_root,
    new_block_number: new_block_number,
    batch_data_hash: batch_data_hash,
    pre_state_root: pre_state_root,
    proof_field_a: proof_field_a,
    proof_field_b: proof_field_b,
    proof_field_c: proof_field_c,
    merkle_leaf: leaf,
    merkle_proof: proof,
    merkle_index: LEAF_INDEX,
  }
end

RSpec.describe StateCovenant do
  it 'starts with initial state' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    expect(c.state_root).to eq(GENESIS_STATE_ROOT)
    expect(c.block_number).to eq(0)
  end

  it 'advances state with valid proof' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
    }.not_to raise_error
    expect(c.state_root).to eq(args[:new_state_root])
    expect(c.block_number).to eq(1)
  end

  it 'chains multiple advances (0 -> 1 -> 2 -> 3)' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    pre = GENESIS_STATE_ROOT
    (1..3).each do |block|
      args = build_advance_args(pre, block)
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
      expect(c.block_number).to eq(block)
      pre = args[:new_state_root]
    end
  end

  it 'rejects wrong pre-state root' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], 'ff' * 32,
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
    }.to raise_error(RuntimeError)
  end

  it 'rejects non-increasing block number' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 5, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 3)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
    }.to raise_error(RuntimeError)
  end

  it 'rejects invalid Baby Bear proof' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], 99_999,
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
    }.to raise_error(RuntimeError)
  end

  it 'rejects invalid Merkle proof (wrong leaf)' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        args[:batch_data_hash], args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        'aa' * 32, args[:merkle_proof], args[:merkle_index]
      )
    }.to raise_error(RuntimeError)
  end

  it 'rejects wrong batch data hash' do
    c = StateCovenant.new(GENESIS_STATE_ROOT, 0, VERIFYING_KEY_HASH)
    args = build_advance_args(GENESIS_STATE_ROOT, 1)
    expect {
      c.advance_state(
        args[:new_state_root], args[:new_block_number],
        'bb' * 32, args[:pre_state_root],
        args[:proof_field_a], args[:proof_field_b], args[:proof_field_c],
        args[:merkle_leaf], args[:merkle_proof], args[:merkle_index]
      )
    }.to raise_error(RuntimeError)
  end
end
