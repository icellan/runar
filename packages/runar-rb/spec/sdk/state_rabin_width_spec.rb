# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# F-035: RabinPubKey / RabinSig state fields are a bare 8-byte OP_NUM2BIN word,
# exactly like bigint. Both are bigint aliases and every compiler writes and
# reads them that way in the state section (the compiler is canonical, user
# decision D2). The SDK width table omitted both, so they fell to the push-data
# branch, where an Integer is not a String and became '' -- OP_0, the value
# silently lost.
#
# RABIN_STATE_GOLDEN is hand-derived and byte-identical across all seven SDKs
# (the same three values are the `state-rabin` sdk-output fixture):
#
#   RabinPubKey 0x1234567890ABCDEF -> efcdab9078563412
#   RabinSig    -1000000007        -> 07ca9a3b00000080
#   bigint      3                  -> 0300000000000000
#
# Proves: the Ruby codec writes and reads that layout. Does not prove the
# script accepts it (packages/runar-testing f035-rabin-state-spend.test.ts).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State Rabin field widths' do
  # rubocop:enable RSpec/DescribeClass

  def field(name, type, index)
    Runar::SDK::StateField.new(name: name, type: type, index: index)
  end

  let(:golden) { 'efcdab9078563412' + '07ca9a3b00000080' + '0300000000000000' }
  let(:fields) do
    [field('oracleKey', 'RabinPubKey', 0), field('lastSig', 'RabinSig', 1), field('count', 'bigint', 2)]
  end
  let(:values) { { 'oracleKey' => 0x1234567890ABCDEF, 'lastSig' => -1_000_000_007, 'count' => 3 } }

  it 'serializes RabinPubKey / RabinSig as NUM2BIN 8' do
    expect(Runar::SDK::State.serialize_state(fields, values)).to eq(golden)
  end

  it 'deserializes them back' do
    expect(Runar::SDK::State.deserialize_state(fields, golden)).to eq(values)
  end

  it 'refuses a Rabin value that does not fit the 8-byte word' do
    expect do
      Runar::SDK::State.serialize_state([field('k', 'RabinPubKey', 0)], { 'k' => 1 << 63 })
    end.to raise_error(ArgumentError, /does not fit/)
  end
end
