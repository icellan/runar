# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe Runar::Analyzer::PathAnalyzer do
  it 'detects unbalanced OP_ENDIF' do
    ops = Runar::Analyzer::ScriptParser.parse('68')
    res = described_class.analyze(ops)
    expect(res[:paths]).to eq([])
    expect(res[:findings].first[:code]).to eq('UNBALANCED_IF_ENDIF')
    expect(res[:findings].first[:message]).to eq('OP_ENDIF without matching OP_IF')
  end

  it 'detects unbalanced OP_ELSE' do
    ops = Runar::Analyzer::ScriptParser.parse('67')
    res = described_class.analyze(ops)
    expect(res[:findings].first[:message]).to eq('OP_ELSE without matching OP_IF')
  end

  it 'detects unclosed OP_IF' do
    ops = Runar::Analyzer::ScriptParser.parse('63')
    res = described_class.analyze(ops)
    expect(res[:findings].first[:code]).to eq('UNBALANCED_IF_ENDIF')
    expect(res[:findings].first[:message]).to match(/OP_IF at offset 0 has no matching OP_ENDIF/)
  end

  it 'produces a single linear path when there are no branches' do
    ops = Runar::Analyzer::ScriptParser.parse('76a988ac')
    res = described_class.analyze(ops)
    expect(res[:paths].length).to eq(1)
    expect(res[:paths][0][:description]).to eq('linear (no branches)')
    expect(res[:paths][0][:branch_choices]).to eq([])
  end

  it 'enumerates 2 paths for a single OP_IF' do
    # OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    ops = Runar::Analyzer::ScriptParser.parse('51635267536800')
    res = described_class.analyze(ops)
    expect(res[:paths].length).to eq(2)
    expect(res[:paths][0][:description]).to eq('IF[false] at 1')
    expect(res[:paths][1][:description]).to eq('IF[true] at 1')
  end

  it 'renders symbolic path count for large numBranches (spec v1.2)' do
    # Spec v1.2: numBranches >= 53 renders "more than 2^53 paths" instead
    # of an exact decimal (would overflow JS safe-integer range).
    # Use 53 OP_IF / OP_ENDIF pairs.
    hex = ('6368' * 53)
    ops = Runar::Analyzer::ScriptParser.parse(hex)
    res = described_class.analyze(ops)
    truncated = res[:findings].find { |f| f[:code] == 'PATHS_TRUNCATED' }
    expect(truncated).not_to be_nil
    expect(truncated[:message]).to include('Script has 53 branch points (more than 2^53 paths)')
  end

  it 'emits PATHS_TRUNCATED when requested combinations > 256' do
    # 9 branches => 512 requested combos. Easiest construction:
    # 9 copies of `OP_IF OP_ENDIF`.
    hex = ('6368' * 9)
    ops = Runar::Analyzer::ScriptParser.parse(hex)
    res = described_class.analyze(ops)
    truncated = res[:findings].find { |f| f[:code] == 'PATHS_TRUNCATED' }
    expect(truncated).not_to be_nil
    expect(truncated[:message]).to include('512 paths')
    expect(truncated[:message]).to include('truncated to the first 256')
    expect(res[:paths].length).to eq(256)
  end

  it 'INCONSISTENT_BRANCH_DEPTH on no-ELSE branch with non-zero delta' do
    # OP_1 OP_IF OP_DUP OP_ENDIF — DUP has delta +1
    ops = Runar::Analyzer::ScriptParser.parse('5163' + '76' + '68')
    res = described_class.analyze(ops)
    finding = res[:findings].find { |f| f[:code] == 'INCONSISTENT_BRANCH_DEPTH' }
    expect(finding).not_to be_nil
    expect(finding[:message]).to include('net stack delta 1')
  end
end
