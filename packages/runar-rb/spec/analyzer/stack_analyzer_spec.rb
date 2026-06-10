# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe Runar::Analyzer::StackAnalyzer do
  def parse(hex)
    Runar::Analyzer::ScriptParser.parse(hex)
  end

  it 'computes negative final depth for a locking-script consumer (no underflow at initial 0)' do
    # OP_DUP OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG (basic P2PKH suffix)
    ops = parse('76a988ac')
    result = described_class.analyze(ops, initial_depth: 0)
    expect(result[:findings]).to eq([])
    # 76 OP_DUP (+1), a9 OP_HASH160 (0), 88 OP_EQUALVERIFY (-2), ac OP_CHECKSIG (-1)
    expect(result[:depth]).to eq(-2)
  end

  it 'emits STACK_UNDERFLOW only when initial_depth > 0' do
    ops = parse('75') # OP_DROP requires 1 item
    no_underflow = described_class.analyze(ops, initial_depth: 0)
    expect(no_underflow[:findings]).to eq([])

    # If initial_depth is 0 but ops include something requiring more...
    ops_underflow = parse('6d') # OP_2DROP requires 2 items
    res = described_class.analyze(ops_underflow, initial_depth: 1)
    expect(res[:findings].first[:code]).to eq('STACK_UNDERFLOW')
  end

  it 'emits UNREACHABLE_AFTER_RETURN after OP_RETURN' do
    ops = parse('6a76') # OP_RETURN OP_DUP
    result = described_class.analyze(ops, initial_depth: 0)
    expect(result[:findings].first[:code]).to eq('UNREACHABLE_AFTER_RETURN')
    expect(result[:findings].first[:opcode]).to eq('OP_DUP')
  end

  it 'computes flat_delta across an ELSE-less range' do
    # 76 (OP_DUP: pops 1, pushes 2 -> delta +1)
    ops = parse('76')
    expect(described_class.flat_delta(ops, 0, 1)).to eq(1)
  end

  it 'returns nil for ranges containing nested OP_IF/OP_NOTIF' do
    ops = parse('63')
    expect(described_class.flat_delta(ops, 0, 1)).to be_nil
  end
end
