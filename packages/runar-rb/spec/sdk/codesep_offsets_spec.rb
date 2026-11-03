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

# Issue #132: get_code_sep_index must byte-walk the real @code_script when it
# is set (chain-loaded / restore path), rather than deriving the offset from
# the in-memory constructor args (which are 0 placeholders after from_utxo /
# from_txid). The OP_PUSH_TX signature would otherwise be computed over the
# wrong scriptCode when the args don't match the bytes baked into @code_script.
RSpec.describe Runar::SDK::RunarContract, '#get_code_sep_index (issue #132)' do
  # code_separator_index template offset = 2; a constructor slot sits before it,
  # so adjust_code_sep_offset (the template path) is args-dependent. The real
  # on-chain script places OP_CODESEPARATOR at byte 22 (after a 20-byte ctor
  # push), which the byte-walk must recover regardless of the in-memory args.
  let(:artifact_json) do
    JSON.generate(
      version: '1.0',
      compilerVersion: '0.1.0',
      contractName: 'CodeSep',
      abi: { constructor: { params: [{ name: 'x', type: 'Addr' }] },
             methods: [{ name: 'm', params: [], isPublic: true }] },
      script: '51',
      asm: '',
      stateFields: [],
      constructorSlots: [{ paramIndex: 0, byteOffset: 1 }],
      codeSeparatorIndex: 2
    )
  end

  let(:artifact) { Runar::SDK::RunarArtifact.from_json(artifact_json) }

  # OP_1, push-20 (0xaa..), OP_CODESEPARATOR at byte 22, OP_CHECKSIG.
  let(:real_code_script) { "5114#{'aa' * 20}abac" }

  it 'byte-walks @code_script and ignores 0 placeholder constructor args' do
    contract = described_class.new(artifact, [0], restoring: true) # placeholder ctor arg (restore path; N-330)
    contract.instance_variable_set(:@code_script, real_code_script)
    # Byte-walk recovers the true OP_CODESEPARATOR byte offset (22)...
    expect(contract.send(:get_code_sep_index, 0)).to eq(22)
  end

  it 'falls back to the args-derived template offset when @code_script is nil' do
    contract = described_class.new(artifact, [0], restoring: true)
    # ...whereas the template path (no @code_script) returns the base offset (2).
    expect(contract.send(:get_code_sep_index, 0)).to eq(2)
    expect(contract.send(:get_code_sep_index, 0)).not_to eq(22)
  end
end
