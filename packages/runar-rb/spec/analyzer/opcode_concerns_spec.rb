# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe Runar::Analyzer::OpcodeConcerns do
  it 'emits CODESEPARATOR_PRESENT for each OP_CODESEPARATOR' do
    ops = Runar::Analyzer::ScriptParser.parse('ab00ab')
    findings = described_class.analyze(ops, 3)
    matched = findings.select { |f| f[:code] == 'CODESEPARATOR_PRESENT' }
    expect(matched.length).to eq(2)
    expect(matched[0][:offset]).to eq(0)
    expect(matched[1][:offset]).to eq(2)
  end

  it 'emits INEFFICIENT_PUSH for OP_PUSHDATA1 of ≤75 bytes' do
    ops = Runar::Analyzer::ScriptParser.parse('4c02aabb')
    findings = described_class.analyze(ops, 4)
    pp = findings.find { |f| f[:code] == 'INEFFICIENT_PUSH' }
    expect(pp).not_to be_nil
    expect(pp[:message]).to include('OP_PUSHDATA1 used for 2-byte data')
    expect(pp[:message]).to include('opcode 0x02')
  end

  it 'emits INEFFICIENT_PUSH for OP_PUSHDATA2 of ≤255 bytes' do
    ops = Runar::Analyzer::ScriptParser.parse('4d0200aabb')
    findings = described_class.analyze(ops, 5)
    pp = findings.find { |f| f[:code] == 'INEFFICIENT_PUSH' }
    expect(pp).not_to be_nil
    expect(pp[:message]).to include('OP_PUSHDATA2 used for 2-byte data')
    expect(pp[:message]).to include('OP_PUSHDATA1 would be more efficient')
  end

  it 'emits LARGE_SCRIPT when script size > 500_000 bytes' do
    # Use a synthetic >500_000-byte ops list of OP_NOPs.
    hex = '61' * 600_000
    ops = Runar::Analyzer::ScriptParser.parse(hex)
    findings = described_class.analyze(ops, 600_000)
    large = findings.find { |f| f[:code] == 'LARGE_SCRIPT' }
    expect(large).not_to be_nil
    expect(large[:message]).to include('Script is 600000 bytes')
    expect(large[:message]).to include(' KB)')
  end

  it 'format_kb matches JS (n/1024).toFixed(1)' do
    expect(described_class.format_kb(1024)).to eq('1.0')
    expect(described_class.format_kb(1536)).to eq('1.5')
    expect(described_class.format_kb(600_000)).to eq('585.9')
    # banker's rounding: 1024*0.5 / 10 boundary. 0.05 KB -> 51.2 bytes.
    # Round half to even: pick a clean case 1024 -> 1.0, no halfway.
  end
end
