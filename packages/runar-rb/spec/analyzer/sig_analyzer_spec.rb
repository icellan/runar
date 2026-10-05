# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe Runar::Analyzer::SigAnalyzer do
  it 'flags CHECKSIG_RESULT_DROPPED when OP_CHECKSIG is immediately followed by OP_DROP' do
    ops = Runar::Analyzer::ScriptParser.parse('ac75')
    findings = described_class.analyze(ops, [])
    finding = findings.find { |f| f[:code] == 'CHECKSIG_RESULT_DROPPED' }
    expect(finding).not_to be_nil
    expect(finding[:opcode]).to eq('OP_CHECKSIG')
  end

  # F-234: OP_2DROP pops the CHECKSIG result as surely as OP_DROP does, so
  # `OP_CHECKSIG OP_2DROP OP_1` used to verify clean. Proves the immediate
  # OP_2DROP form is flagged with the spec §5.1 message and that OP_NIP (which
  # removes the item BELOW the result) is not. Does not prove that longer
  # discard sequences (OP_SWAP OP_NIP, OP_TOALTSTACK, ...) are caught: the rule
  # only looks at the next opcode.
  it 'flags CHECKSIG_RESULT_DROPPED when OP_CHECKSIG/OP_CHECKMULTISIG is followed by OP_2DROP (F-234)' do
    [
      ['0000ac6d51', 'OP_CHECKSIG result is dropped by OP_2DROP — signature check has no effect', 2],
      ['000000ae6d51', 'OP_CHECKMULTISIG result is dropped by OP_2DROP — signature check has no effect', 3]
    ].each do |hex, want, offset|
      ops = Runar::Analyzer::ScriptParser.parse(hex)
      got = described_class.analyze(ops, []).select { |f| f[:code] == 'CHECKSIG_RESULT_DROPPED' }
      expect(got.size).to eq(1)
      expect(got.first[:message]).to eq(want)
      expect(got.first[:severity]).to eq('warning')
      expect(got.first[:offset]).to eq(offset)
    end
    # OP_0 OP_0 OP_CHECKSIG OP_NIP — the result survives on top; not flagged.
    ops = Runar::Analyzer::ScriptParser.parse('0000ac77')
    expect(described_class.analyze(ops, []).any? { |f| f[:code] == 'CHECKSIG_RESULT_DROPPED' }).to eq(false)
  end

  it 'does NOT flag CHECKSIG_VERIFY (no stack result)' do
    ops = Runar::Analyzer::ScriptParser.parse('ad75')
    findings = described_class.analyze(ops, [])
    expect(findings.any? { |f| f[:code] == 'CHECKSIG_RESULT_DROPPED' }).to eq(false)
  end

  it 'emits NO_SIG_CHECK for reachable paths without CHECKSIG' do
    paths = [{ reachable: true, has_check_sig: false, description: 'linear (no branches)' }]
    findings = described_class.analyze([], paths)
    expect(findings.first[:code]).to eq('NO_SIG_CHECK')
    expect(findings.first[:path]).to eq('linear (no branches)')
  end
end
