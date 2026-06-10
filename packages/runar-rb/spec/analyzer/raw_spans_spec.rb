# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe 'collapse_raw_script_spans' do
  it 'leaves opcodes unchanged when no spans are provided' do
    ops = Runar::Analyzer::ScriptParser.parse('76a988ac')
    result = Runar::Analyzer.collapse_raw_script_spans(ops, [])
    expect(result).to eq(ops)
  end

  it 'collapses opcodes inside a span into a single synthetic RAW_SPAN' do
    # 5 single-byte opcodes: offsets 0..4
    ops = Runar::Analyzer::ScriptParser.parse('7676767676')
    span = [{ offset: 1, length: 3, in_arity: 2, out_arity: 3 }]
    result = Runar::Analyzer.collapse_raw_script_spans(ops, span)
    expect(result.length).to eq(3)
    expect(result[0][:name]).to eq('OP_DUP')
    expect(result[1][:name]).to eq('RAW_SPAN')
    expect(result[1][:opcode]).to eq(-1)
    expect(result[1][:offset]).to eq(1)
    expect(result[1][:size]).to eq(3)
    expect(result[1][:raw_span_arity]).to eq([2, 3])
    expect(result[2][:name]).to eq('OP_DUP')
  end

  it 'silently ignores spans past the parsed stream' do
    ops = Runar::Analyzer::ScriptParser.parse('76')
    span = [{ offset: 100, length: 5, in_arity: 0, out_arity: 0 }]
    result = Runar::Analyzer.collapse_raw_script_spans(ops, span)
    expect(result).to eq(ops)
  end
end
