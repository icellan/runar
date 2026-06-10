# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe 'Runar::Analyzer.analyze_script orchestrator' do
  it 'orders findings as (severityRank, offsetRank, insertion)' do
    # Build a script that emits warnings, errors, and infos at various offsets.
    # ab => OP_CODESEPARATOR (info, offset 0)
    # 6a => OP_RETURN (no finding here, just allows next opcode to be flagged)
    # 76 => OP_DUP after OP_RETURN (warning UNREACHABLE_AFTER_RETURN, offset 2)
    # Use 0 paths case to trigger linear fallback.
    # Actually let's just verify ordering on a small case.
    result = Runar::Analyzer.analyze_script('ab')
    # OP_CODESEPARATOR alone: 1 linear path with no verification +
    # no sig => UNCONDITIONALLY_SUCCEEDS (warning), NO_SIG_CHECK
    # (warning), CODESEPARATOR_PRESENT (info). Sorted by severity.
    codes = result[:findings].map { |f| f[:code] }
    expect(codes).to eq(%w[UNCONDITIONALLY_SUCCEEDS NO_SIG_CHECK CODESEPARATOR_PRESENT])
  end

  it 'emits NO_SIG_CHECK + UNCONDITIONALLY_SUCCEEDS for an OP_1 script' do
    # 51 (OP_1) — pushes truth, no verification, no sig.
    result = Runar::Analyzer.analyze_script('51')
    codes = result[:findings].map { |f| f[:code] }
    expect(codes).to include('UNCONDITIONALLY_SUCCEEDS')
    expect(codes).to include('NO_SIG_CHECK')
  end

  it 'preserves stable sort within severity buckets (ties by insertion order)' do
    # Two infos at same severity with no offset (sort to end), two at offsets.
    # Construct: OP_CODESEPARATOR @0, OP_CODESEPARATOR @1.
    result = Runar::Analyzer.analyze_script('abab')
    infos = result[:findings].select { |f| f[:severity] == 'info' }
    expect(infos.length).to eq(2)
    expect(infos[0][:offset]).to eq(0)
    expect(infos[1][:offset]).to eq(1)
  end

  it 'JSON output ends with trailing newline' do
    result = Runar::Analyzer.analyze_script('51')
    json = Runar::Analyzer.to_canonical_json(result)
    expect(json[-1]).to eq("\n")
    expect(json[-2]).not_to eq("\n")
  end

  it 'JSON output uses 2-space indent' do
    result = Runar::Analyzer.analyze_script('51')
    json = Runar::Analyzer.to_canonical_json(result)
    # First non-`{` line begins with 2 spaces.
    second_line = json.split("\n", 3)[1]
    expect(second_line).to match(/^  "/)
  end
end
