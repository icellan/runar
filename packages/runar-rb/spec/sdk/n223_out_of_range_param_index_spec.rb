# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'
require 'json'

# N-223 — out-of-range constructorSlots paramIndex.
#
# The constructor only checks `constructor_args.length == abi.constructor.params.length`
# (RunarContract#initialize) -- it never cross-checks that every
# constructor_slots[].param_index actually falls within that range. A malformed
# or hostile artifact can declare a slot whose param_index is out of bounds.
#
# Before this fix, every `@constructor_args[slot.param_index]` read in
# contract.rb (build_code_script, adjust_code_sep_offset,
# resolved_code_sep_slot_values) indexed the array directly: an out-of-range
# positive index returned `nil`, and `encode_arg`'s fallback branch
# (`value.to_s` -> `''` -> `State.encode_push_data('')`, an empty push, i.e.
# OP_0) silently spliced a wrong-but-valid script instead of refusing. (TS's
# equivalent bug spliced the literal ASCII bytes of "undefined" -- see
# N-081 -- because JS's `String(undefined)` is non-empty; Ruby's failure mode
# is OP_0, which is what this item's brief calls "Ruby splices OP_0 (nil)".)
#
# See N-081 (packages/runar-sdk/src/__tests__/constructor-slots.test.ts) for
# the TypeScript SDK's version of the same fix, and this item's brief for the
# cross-tier scope (all 7 SDKs).
RSpec.describe Runar::SDK::RunarContract, 'N-223: out-of-range constructorSlots paramIndex' do
  let(:artifact_json) do
    JSON.generate(
      version: '1.0',
      compilerVersion: '0.1.0',
      contractName: 'Test',
      abi: { constructor: { params: [{ name: 'threshold', type: 'bigint' }] },
             methods: [{ name: 'check', params: [], isPublic: true }] },
      # OP_0(slot) OP_NUMEQUAL OP_VERIFY
      script: '009c69',
      asm: '',
      stateFields: [],
      # Exactly 1 constructor arg below (matching the 1 ABI param), but the
      # slot references paramIndex 1 -- out of range.
      constructorSlots: [{ paramIndex: 1, byteOffset: 0 }]
    )
  end
  let(:artifact) { Runar::SDK::RunarArtifact.from_json(artifact_json) }
  let(:contract) { described_class.new(artifact, [1000]) }

  it 'raises a named ArgumentError from get_locking_script (build_code_script), instead of splicing OP_0' do
    expect { contract.get_locking_script }.to raise_error(ArgumentError, /paramIndex/)
  end

  # This proves the gap the primary-site fix alone does not cover:
  # adjust_code_sep_offset / resolved_code_sep_slot_values are independently
  # reachable (via get_code_sep_index, used by every BIP-143 signing path) and
  # read @constructor_args without going through build_code_script first.
  let(:codesep_artifact_json) do
    JSON.generate(
      version: '1.0',
      compilerVersion: '0.1.0',
      contractName: 'CodeSep',
      abi: { constructor: { params: [{ name: 'threshold', type: 'bigint' }] },
             methods: [{ name: 'check', params: [], isPublic: true }] },
      # OP_0(slot) OP_CODESEPARATOR OP_NUMEQUAL OP_VERIFY
      script: '00ab9c69',
      asm: '',
      stateFields: [],
      constructorSlots: [{ paramIndex: 1, byteOffset: 0 }],
      codeSeparatorIndex: 2
    )
  end
  let(:codesep_artifact) { Runar::SDK::RunarArtifact.from_json(codesep_artifact_json) }
  let(:codesep_contract) { described_class.new(codesep_artifact, [1000]) }

  it 'raises a named ArgumentError from adjust_code_sep_offset (via get_code_sep_index), with no @code_script set' do
    expect { codesep_contract.send(:get_code_sep_index, 0) }.to raise_error(ArgumentError, /paramIndex/)
  end
end
