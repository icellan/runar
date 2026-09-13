# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'runar/sdk'

# R-178 (CL-BUG-071): an out-of-range code_separator_index used to return the
# UNTRIMMED script, so a fund-moving signature was computed over a wrong
# scriptCode with no error. All seven SDKs mishandled this in four different
# ways; every tier now refuses and names the input.
RSpec.describe 'R-178: code_separator_index range' do
  let(:scenario) do
    path = File.expand_path('../../../../../../conformance/sdk-bip143/fixtures.json', __FILE__)
    JSON.parse(File.read(path))['scenarios'].first
  end

  it 'refuses an index past the end of the script' do
    script = scenario['prevScriptHex']
    past_the_end = script.length / 2

    [past_the_end, past_the_end + 1, past_the_end + 99].each do |idx|
      expect do
        Runar::SDK.get_subscript(script, idx)
      end.to raise_error(ArgumentError, /code_separator_index/),
             "index #{idx} past the end was accepted"
    end
  end

  it 'still trims for an in-range index' do
    script = scenario['prevScriptHex']
    expect(Runar::SDK.get_subscript(script, 0)).to eq(script[2..])
    expect(Runar::SDK.get_subscript(script, -1)).to eq(script)
  end
end
