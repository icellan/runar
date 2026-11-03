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

# N-155: code_separator_index pointing at the LAST byte of the subscript
# passes R-178's "past the end" check (trim_pos == length, not >), so
# get_subscript still returns '' (asserted above, by design -- it is a
# public, independently-tested low-level slicing helper). compute_op_push_tx
# is the function that actually builds a preimage, and it must refuse that
# empty scriptCode the same way it refuses a bare empty subscript. Proves:
# compute_op_push_tx refuses this case. Does not prove anything about
# ExternalSigner#sign (it already rejects any empty string it is handed) or
# about callers upstream that compute the code_separator_index they pass in.
RSpec.describe 'N-155: code_separator_index on the subscript\'s last byte' do
  it 'is refused by compute_op_push_tx' do
    tx_hex = '01000000' \
             "01#{'11' * 32}00000000" \
             '00' \
             'ffffffff' \
             '01' \
             'e803000000000000' \
             '0151' \
             '00000000'
    one_byte = '51' # OP_1 -- code_separator_index 0 is its last (and only) byte

    expect do
      Runar::SDK.compute_op_push_tx(tx_hex, 0, one_byte, 1000, 0)
    end.to raise_error(ArgumentError, /empty subscript/)
  end
end
