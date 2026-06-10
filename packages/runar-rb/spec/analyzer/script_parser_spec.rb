# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe Runar::Analyzer::ScriptParser do
  it 'parses single-byte opcodes with canonical names' do
    ops = described_class.parse('76a988ac')
    expect(ops.map { |o| o[:name] }).to eq(['OP_DUP', 'OP_HASH160', 'OP_EQUALVERIFY', 'OP_CHECKSIG'])
    expect(ops.map { |o| o[:offset] }).to eq([0, 1, 2, 3])
  end

  it 'renames OP_0 and OP_1 from aliases' do
    ops = described_class.parse('0051')
    expect(ops.map { |o| o[:name] }).to eq(['OP_0', 'OP_1'])
  end

  it 'names direct pushes PUSH_<n>' do
    # 0x02 = direct push of 2 bytes
    ops = described_class.parse('02aabb')
    expect(ops.length).to eq(1)
    expect(ops[0][:name]).to eq('PUSH_2')
    expect(ops[0][:size]).to eq(3)
    expect(ops[0][:data_length]).to eq(2)
  end

  it 'parses OP_PUSHDATA1 with length byte' do
    # 4c 02 aa bb => pushdata1 of 2 bytes
    ops = described_class.parse('4c02aabb')
    expect(ops.length).to eq(1)
    expect(ops[0][:name]).to eq('OP_PUSHDATA1')
    expect(ops[0][:data_length]).to eq(2)
    expect(ops[0][:size]).to eq(4)
    expect(ops[0][:push_encoding]).to eq(:pushdata1)
  end

  it 'parses OP_PUSHDATA2 little-endian length' do
    # 4d 02 00 aa bb
    ops = described_class.parse('4d0200aabb')
    expect(ops.length).to eq(1)
    expect(ops[0][:name]).to eq('OP_PUSHDATA2')
    expect(ops[0][:data_length]).to eq(2)
  end

  it 'renders unknown opcodes as OP_UNKNOWN(0xNN)' do
    ops = described_class.parse('62')
    expect(ops.length).to eq(1)
    expect(ops[0][:name]).to eq('OP_UNKNOWN(0x62)')
  end

  it 'silently truncates over-long pushes and stops parsing' do
    # 03 aabb : declares 3 data bytes, only 2 available
    ops = described_class.parse('03aabb')
    expect(ops.length).to eq(1)
    expect(ops[0][:name]).to eq('PUSH_3')
    # No additional finding here; truncation is observed downstream.
  end
end
