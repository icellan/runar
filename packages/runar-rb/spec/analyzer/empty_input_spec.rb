# frozen_string_literal: true

require 'spec_helper'
require 'runar/analyzer'

RSpec.describe 'empty input' do
  it 'returns INVALID_TERMINAL_STACK for empty hex' do
    result = Runar::Analyzer.analyze_script('')
    expect(result[:script]).to eq('')
    expect(result[:script_size]).to eq(0)
    expect(result[:findings].length).to eq(1)
    expect(result[:findings][0][:code]).to eq('INVALID_TERMINAL_STACK')
    expect(result[:findings][0][:message]).to eq('Empty script — no opcodes to execute')
    expect(result[:paths]).to eq([])
    expect(result[:summary][:total_paths]).to eq(0)
  end

  it 'normalizes whitespace + casing' do
    result = Runar::Analyzer.analyze_script("  76\nA9\t88AC  ")
    expect(result[:script]).to eq('76a988ac')
    expect(result[:script_size]).to eq(4)
  end
end
