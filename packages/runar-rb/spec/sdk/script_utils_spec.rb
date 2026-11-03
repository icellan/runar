# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::ScriptUtils.extract_constructor_args' do
  # rubocop:enable RSpec/DescribeClass

  # A param referenced N times in the contract body emits N constructor slots.
  # Every occurrence's encoded width shifts the offsets of everything after it,
  # so the extractor must account for ALL occurrences — not just the first per
  # param. Regression for a bug where slots were deduplicated by param_index
  # BEFORE the offset walk, mis-reading every later slot whenever an earlier
  # repeated value encoded wider than its 1-byte template placeholder.
  #
  # Template: ab <00> 7c <00> 7c <00> ac
  #   offset 1: alpha (param_index 0)
  #   offset 3: alpha again (param_index 0 — second reference)
  #   offset 5: beta  (param_index 1)
  # Resolved with alpha = 500 (scriptnum push `02f401`, 3 bytes) and
  # beta = 7 (OP_7, 1 byte):
  #   ab 02f401 7c 02f401 7c 57 ac
  def repeated_slot_artifact
    Runar::SDK::RunarArtifact.new(
      script: 'ab' + '00' + '7c' + '00' + '7c' + '00' + 'ac',
      constructor_slots: [
        Runar::SDK::ConstructorSlot.new(param_index: 0, byte_offset: 1),
        Runar::SDK::ConstructorSlot.new(param_index: 0, byte_offset: 3),
        Runar::SDK::ConstructorSlot.new(param_index: 1, byte_offset: 5)
      ],
      abi: Runar::SDK::ABI.new(
        constructor_params: [
          Runar::SDK::ABIParam.new(name: 'alpha', type: 'bigint'),
          Runar::SDK::ABIParam.new(name: 'beta', type: 'bigint')
        ]
      )
    )
  end

  it 'reads slots AFTER a repeated wide value at the correct offsets' do
    resolved = 'ab' + '02f401' + '7c' + '02f401' + '7c' + '57' + 'ac'
    args = Runar::SDK::ScriptUtils.extract_constructor_args(repeated_slot_artifact, resolved)

    expect(args['alpha']).to eq(500)
    # Before the fix, the second alpha occurrence's +2 byte shift was dropped,
    # so beta was read from inside the second alpha push and decoded as 124.
    expect(args['beta']).to eq(7)
  end

  it 'still extracts correctly when the repeated value fits its placeholder width' do
    # alpha = 5 → OP_5 (1 byte, same width as the placeholder: zero shift).
    resolved = 'ab' + '55' + '7c' + '55' + '7c' + '57' + 'ac'
    args = Runar::SDK::ScriptUtils.extract_constructor_args(repeated_slot_artifact, resolved)

    expect(args['alpha']).to eq(5)
    expect(args['beta']).to eq(7)
  end
end

# F-238 — read_script_element must refuse malformed provider-supplied scripts
# instead of raising a bare ArgumentError/TypeError or silently truncating.
#
# Before this fix, `hex[offset, 2].to_i(16)` raised an uncaught
# ArgumentError/TypeError when `offset` ran past the end of the string (`nil`
# has no `to_i(16)`), and a push whose declared length ran past the remaining
# bytes silently returned a SHORT data_hex (`hex[offset+2, data_len] || ''`
# just takes whatever Ruby's slicing leaves) instead of erroring — which
# extract_constructor_args / matches_artifact then treat as a valid (wrong)
# element, corrupting every later slot's offset in the same walk.
#
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::ScriptUtils malformed-script rejection (F-238)' do
  # rubocop:enable RSpec/DescribeClass

  MALFORMED_VECTORS = [
    '',           # no opcode byte at all
    'f',          # odd-length hex, can't even form an opcode byte
    '05aabb',     # direct push declares 5 bytes, only 2 remain
    '4c',         # OP_PUSHDATA1 with no length byte
    '4c05aa',     # OP_PUSHDATA1 declares 5 bytes, only 1 remains
    '4d0100',     # OP_PUSHDATA2 length prefix present, 0 of the 1 declared bytes remain
    '4e01000000'  # OP_PUSHDATA4 length prefix present, 0 of the 1 declared bytes remain
  ].freeze

  def one_slot_artifact(type = 'bigint')
    Runar::SDK::RunarArtifact.new(
      script: '00ac',
      constructor_slots: [Runar::SDK::ConstructorSlot.new(param_index: 0, byte_offset: 0)],
      abi: Runar::SDK::ABI.new(constructor_params: [Runar::SDK::ABIParam.new(name: 'x', type: type)])
    )
  end

  describe '.read_script_element' do
    MALFORMED_VECTORS.each do |hex|
      it "refuses #{hex.inspect}" do
        expect { Runar::SDK::ScriptUtils.read_script_element(hex, 0) }
          .to raise_error(Runar::SDK::MalformedScriptError)
      end
    end

    it 'still decodes valid pushes of every pushdata flavour unchanged' do
      expect(Runar::SDK::ScriptUtils.read_script_element('012a', 0))
        .to eq(data_hex: '2a', total_hex_chars: 4, opcode: 0x01)
      expect(Runar::SDK::ScriptUtils.read_script_element('4c012a', 0))
        .to eq(data_hex: '2a', total_hex_chars: 6, opcode: 0x4C)
      expect(Runar::SDK::ScriptUtils.read_script_element('4d01002a', 0))
        .to eq(data_hex: '2a', total_hex_chars: 8, opcode: 0x4D)
      expect(Runar::SDK::ScriptUtils.read_script_element('4e010000002a', 0))
        .to eq(data_hex: '2a', total_hex_chars: 12, opcode: 0x4E)
    end
  end

  describe '.extract_constructor_args' do
    it 'propagates the rejection on a truncated push' do
      expect { Runar::SDK::ScriptUtils.extract_constructor_args(one_slot_artifact, '05aabb') }
        .to raise_error(Runar::SDK::MalformedScriptError)
    end
  end

  describe '.matches_artifact' do
    it 'propagates the rejection on a truncated push' do
      expect { Runar::SDK::ScriptUtils.matches_artifact(one_slot_artifact, '05aabb') }
        .to raise_error(Runar::SDK::MalformedScriptError)
    end
  end
end
