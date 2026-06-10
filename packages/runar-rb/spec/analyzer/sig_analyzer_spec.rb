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
