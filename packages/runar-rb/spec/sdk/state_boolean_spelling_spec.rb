# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# A mutable `boolean` state field is ONE raw byte — 01 or 00.
#
# The compiler spells the type `boolean`. `bool` appears nowhere in any of the
# seven frontends, so an artifact's stateFields never carries it; the SDKs that
# matched on 'bool' alone were matching a spelling no compiler emits, and every
# real boolean field fell through to their push-data default:
#
#   typescript  01           correct
#   ruby        01           correct
#   go          02 74727565  push-framed ASCII "true" — 3 bytes too long
#   java        02 74727565  same
#   python      00           right width, ALWAYS false
#   zig         00           same
#   rust        panic        as_bytes() on a Bool variant
#
# All five are fund-affecting. Go and Java deploy a state tail longer than the
# one the script's own reader rebuilds, so hash256(outputs) can never match and
# the first spend is impossible. Python and Zig deploy a well-formed tail that
# says false whatever the caller passed, so the first call that sets the flag
# builds a continuation the covenant rejects. Rust fails closed.
#
# cross_sdk_golden is byte-identical across all seven SDKs; every tier carries
# the same literal and the same field list. The trailing bigint is load-bearing:
# a boolean of the wrong WIDTH shifts it, so the record catches a length error
# that a lone boolean field would hide.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State boolean field spelling' do
  # rubocop:enable RSpec/DescribeClass

  def field(name, type, index)
    Runar::SDK::StateField.new(name: name, type: type, index: index)
  end

  let(:fields) do
    [
      field('count', 'bigint', 0),
      # The canonical spelling — the only one any compiler emits.
      field('flag', 'boolean', 1),
      # The alias. Several tiers accepted only this one; it must keep working.
      field('alias', 'bool', 2),
      field('tail', 'bigint', 3),
    ]
  end

  # The one wire record every tier must reproduce byte for byte.
  let(:cross_sdk_golden) do
    '0700000000000000' + # bigint 7, NUM2BIN 8
      '01' +             # boolean true  — 1 raw byte
      '00' +             # bool    false — 1 raw byte
      '0100000000000000' # bigint 1, NUM2BIN 8
  end

  let(:flipped_golden) { "0700000000000000#{'00'}#{'01'}0100000000000000" }

  it 'serializes the cross-SDK golden record byte for byte' do
    expect(cross_sdk_golden.length / 2).to eq(18)
    got = Runar::SDK::State.serialize_state(
      fields, { 'count' => 7, 'flag' => true, 'alias' => false, 'tail' => 1 }
    )
    expect(got).to eq(cross_sdk_golden)
  end

  it 'serializes the opposite polarity, so a constant answer cannot pass' do
    got = Runar::SDK::State.serialize_state(
      fields, { 'count' => 7, 'flag' => false, 'alias' => true, 'tail' => 1 }
    )
    expect(got).to eq(flipped_golden)
  end

  it 'deserializes the golden record back to every input value' do
    back = Runar::SDK::State.deserialize_state(fields, cross_sdk_golden)
    expect(back['count']).to eq(7)
    expect(back['flag']).to be(true)
    expect(back['alias']).to be(false)
    expect(back['tail']).to eq(1)
  end

  it 'deserializes the flipped record too' do
    back = Runar::SDK::State.deserialize_state(fields, flipped_golden)
    expect(back['flag']).to be(false)
    expect(back['alias']).to be(true)
  end

  it 'encodes a lone `boolean` field as exactly one byte' do
    one = [field('v', 'boolean', 0)]
    [[true, '01'], [false, '00']].each do |value, want|
      expect(Runar::SDK::State.serialize_state(one, { 'v' => value })).to eq(want)
      expect(Runar::SDK::State.deserialize_state(one, want)['v']).to be(value)
    end
  end
end
