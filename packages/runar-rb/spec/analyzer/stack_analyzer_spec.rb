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

  # F-131. The seven Chronicle opcodes the compiler emits, with the
  # (pops, pushes) the @bsv/sdk interpreter (Spend.ts) gives them.
  # Proves: each is named per spec §4.1 and modelled with its real stack
  # effect, in the lookup and in the observable report (underflow message,
  # stackDepthAtEnd, maxStackDepth). Does not prove runtime semantics (the
  # analyzer is static) and does not re-derive the arities from the interpreter.
  [
    ['8d', 'OP_2MUL', 1, 1],
    ['8e', 'OP_2DIV', 1, 1],
    ['b3', 'OP_SUBSTR', 3, 1],
    ['b4', 'OP_LEFT', 2, 1],
    ['b5', 'OP_RIGHT', 2, 1],
    ['b6', 'OP_LSHIFTNUM', 2, 1],
    ['b7', 'OP_RSHIFTNUM', 2, 1]
  ].each do |byte, name, pops, pushes|
    it "names 0x#{byte} #{name} and models it as (#{pops}, #{pushes})" do
      op = parse(byte).first
      expect(op[:name]).to eq(name)
      expect(described_class.stack_effect(op)).to eq([pops, pushes])

      # OP_DROP empties a stack of known depth 1, then the opcode needs `pops` items.
      lin = described_class.analyze(parse("75#{byte}"), initial_depth: 1)
      want = "#{name} requires #{pops} stack item(s) but only 0 available"
      expect(lin[:findings].any? { |f| f[:code] == 'STACK_UNDERFLOW' && f[:message] == want }).to be(true)

      # `pops` pushes of OP_1 then the opcode leave exactly `pushes` items.
      result = Runar::Analyzer.analyze_script(('51' * pops) + byte)
      expect(result[:paths].first[:stack_depth_at_end]).to eq(pushes)
      expect(result[:summary][:max_stack_depth]).to eq(pushes)
    end
  end

  it 'keeps the OP_UNKNOWN name and (0, 0) effect for a genuinely unknown byte' do
    op = parse('b8').first
    expect(op[:name]).to eq('OP_UNKNOWN(0xb8)')
    expect(described_class.stack_effect(op)).to eq([0, 0])
  end
end
