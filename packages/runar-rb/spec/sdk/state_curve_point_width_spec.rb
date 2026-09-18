# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# P256Point (64) and P384Point (96) are FIXED-WIDTH RAW state fields.
#
# All seven compilers emit them as fixed raw slices in the state tail, and
# runar-lang's cast constructors hard-assert exactly those widths. The seven
# SDKs used to omit both from their width tables, so they fell through to the
# push-data default and deployed a state section 1 byte (0x40 direct push) or
# 2 bytes (OP_PUSHDATA1 0x60) longer than the script's own on-chain reader
# expects. The deploy succeeded and the FIRST spend failed with
# "OP_NUMEQUALVERIFY requires the top stack item to be truthy" — funds locked.
#
# CROSS_SDK_GOLDEN is byte-identical across all seven SDKs; every tier carries
# the same literal and the same field list.
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State curve-point field widths' do
  # rubocop:enable RSpec/DescribeClass

  def field(name, type, index)
    Runar::SDK::StateField.new(name: name, type: type, index: index)
  end

  let(:fields) do
    [
      field('n', 'bigint', 0),
      field('flag', 'bool', 1),
      field('pk', 'PubKey', 2),
      field('h', 'Sha256', 3),
      field('ad', 'Addr', 4),
      field('pt', 'Point', 5),
      field('p256', 'P256Point', 6),
      field('p384', 'P384Point', 7),
      field('sig', 'Sig', 8),
      field('rab', 'RabinSig', 9),
      field('bs', 'ByteString', 10),
    ]
  end

  let(:values) do
    {
      'n' => 1,
      'flag' => true,
      'pk' => "02#{'aa' * 32}",
      'h' => 'bb' * 32,
      'ad' => 'cc' * 20,
      'pt' => 'dd' * 64,
      'p256' => '11' * 64,
      'p384' => '22' * 96,
      'sig' => "3044#{'ee' * 66}",
      'rab' => 'ff' * 8,
      'bs' => '0011',
    }
  end

  # The one wire record every tier must reproduce byte for byte.
  let(:cross_sdk_golden) do
    '0100000000000000' +           # bigint 1, NUM2BIN 8
      '01' +                       # bool true
      "02#{'aa' * 32}" +           # PubKey    33 raw
      ('bb' * 32) +                # Sha256    32 raw
      ('cc' * 20) +                # Addr      20 raw
      ('dd' * 64) +                # Point     64 raw
      ('11' * 64) +                # P256Point 64 raw  <- was framed "40" + 64
      ('22' * 96) +                # P384Point 96 raw  <- was framed "4c60" + 96
      "443044#{'ee' * 66}" +       # Sig        framed <len><data>
      "08#{'ff' * 8}" +            # RabinSig   framed <len><data>
      '020011'                     # ByteString framed <len><data>
  end

  it 'serializes the cross-SDK golden record byte for byte' do
    expect(cross_sdk_golden.length / 2).to eq(399)
    expect(Runar::SDK::State.serialize_state(fields, values)).to eq(cross_sdk_golden)
  end

  it 'deserializes the golden record back to every input value' do
    back = Runar::SDK::State.deserialize_state(fields, cross_sdk_golden)
    expect(back['n']).to eq(1)
    expect(back['flag']).to be(true)
    %w[pk h ad pt p256 p384 sig rab bs].each do |k|
      expect(back[k]).to eq(values[k]), "field #{k}"
    end
  end

  it 'round-trips a lone curve-point field at its fixed raw width' do
    [['P256Point', 64, '11'], ['P384Point', 96, '22']].each do |type, size, fill|
      one = [field('v', type, 0)]
      v = fill * size
      hex = Runar::SDK::State.serialize_state(one, { 'v' => v })
      expect(hex).to eq(v), type
      expect(hex.length / 2).to eq(size), type
      expect(Runar::SDK::State.deserialize_state(one, hex)['v']).to eq(v), type
    end
  end

  it 'leaves the raw and framed controls byte-unchanged' do
    [['Point', 64], ['PubKey', 33], ['Sha256', 32]].each do |type, size|
      v = 'ab' * size
      got = Runar::SDK::State.serialize_state([field('v', type, 0)], { 'v' => v })
      expect(got).to eq(v), type
    end
    %w[ByteString Sig RabinSig].each do |type|
      v = 'ab' * 64
      got = Runar::SDK::State.serialize_state([field('v', type, 0)], { 'v' => v })
      expect(got).to eq("40#{v}"), type
    end
  end
end
