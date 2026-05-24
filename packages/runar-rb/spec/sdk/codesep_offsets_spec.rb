# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'runar/sdk'

# Issue #42: terminal-method sighash subscript byte-walker.
#
# The on-chain script trims its sighash subscript at the method's
# OP_CODESEPARATOR. #find_codesep_offsets must recover the true byte position by
# walking the script, correctly skipping push-data (which may itself contain a
# 0xab byte) and all BSV push opcodes.
RSpec.describe Runar::SDK::RunarContract, '#find_codesep_offsets (issue #42)' do
  let(:artifact_json) do
    JSON.generate(
      version: '1.0',
      compilerVersion: '0.1.0',
      contractName: 'Test',
      abi: { constructor: { params: [] }, methods: [{ name: 'unlock', params: [], isPublic: true }] },
      script: '51',
      asm: '',
      stateFields: [],
      constructorSlots: []
    )
  end

  let(:contract) do
    described_class.new(Runar::SDK::RunarArtifact.from_json(artifact_json), [])
  end

  it 'returns the real byte position, skipping 0xab inside push-data' do
    # 51            OP_1
    # 02 ab cd      push 2 bytes (0xab inside push-data, must be ignored)
    # ab            OP_CODESEPARATOR  <- real, byte offset 4
    # ac            OP_CHECKSIG
    expect(contract.send(:find_codesep_offsets, '5102abcdabac')).to eq([4])
  end

  it 'handles OP_PUSHDATA1' do
    # 4c (OP_PUSHDATA1) 02 (len) abab (data, contains 0xab) ab (real codesep)
    expect(contract.send(:find_codesep_offsets, '4c02ababab')).to eq([4])
  end

  it 'trims the subscript at the real codesep byte position' do
    full_script = '5102abcdabac' # real codesep at byte index 4
    offsets = contract.send(:find_codesep_offsets, full_script)
    expect(offsets).to eq([4])
    code_sep_idx = offsets.first
    trim_pos = (code_sep_idx + 1) * 2
    subscript = full_script[trim_pos..]
    # Only the OP_CHECKSIG (ac) after the separator remains.
    expect(subscript).to eq('ac')
  end

  it 'returns empty for a script with no OP_CODESEPARATOR' do
    expect(contract.send(:find_codesep_offsets, "76a914#{'00' * 20}88ac")).to eq([])
  end
end
