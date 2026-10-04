# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# The state section is framed <len><data>, never MINIMALDATA.
#
# SCRIPT_VERIFY_MINIMALDATA applies to pushes the interpreter EXECUTES —
# unlocking scripts and spliced constructor args, which encode_push_data still
# handles (see state_spec.rb). The state section is raw data after OP_RETURN in
# the locking script: never executed, never MINIMALDATA-checked, and read back
# by the compiler's on-chain state codec (emitPushDataEncode in
# 05-stack-lower.ts), which understands only <len><data>.
#
# #110 applied the MINIMALDATA short-circuit to the state serializer in all
# seven SDKs and none of the seven compilers. A 1-byte 0x05 state field then
# serialised off-chain as "55" while the script rebuilt it as "0105", so the
# continuation hash never matched (unspendable), and a contract DEPLOYED with
# such a value could not be spent at all (the on-chain reader takes 0x55 as a
# length-85 push).
# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State state-section framing' do
  # rubocop:enable RSpec/DescribeClass

  let(:mod) { Runar::SDK::State }
  let(:fields) { [Runar::SDK::StateField.new(name: 'b', type: 'ByteString', index: 0)] }

  def encode(payload)
    Runar::SDK::State.serialize_state(
      [Runar::SDK::StateField.new(name: 'b', type: 'ByteString', index: 0)],
      { 'b' => payload },
    )
  end

  it 'keeps OP_N-range single bytes as direct pushes' do
    (1..16).each do |n|
      payload = format('%02x', n)
      expect(encode(payload)).to eq("01#{payload}")
    end
  end

  it 'does not collapse 0x81 to OP_1NEGATE' do
    expect(encode('81')).to eq('0181')
  end

  it 'keeps a single zero byte as a direct push' do
    expect(encode('00')).to eq('0100')
  end

  it 'encodes empty as a zero-length push' do
    expect(encode('')).to eq('00')
  end

  it 'leaves values outside the OP_N range unchanged' do
    expect(encode('11')).to eq('0111')
    expect(encode('0011')).to eq('020011')
  end

  it 'round-trips every single-byte value' do
    (0..0xff).each do |b|
      payload = format('%02x', b)
      expect(mod.deserialize_state(fields, encode(payload))).to eq({ 'b' => payload })
    end
  end

  # N-044: the compiler's on-chain state reader and writer frame a ByteString
  # with an UNSIGNED length (<len> below 76, 4c <len8>, 4d <len16 LE>,
  # 4e <len32 LE>), and the covenant only accepts a continuation whose state
  # bytes equal the SDK's. Hand-written expected headers at every boundary
  # where a signed reading of the length used to differ (0x80, 0x81.., 0x8000,
  # 0xffff) and where PUSHDATA4 starts. The on-chain side is run against the
  # same frames by packages/runar-testing/src/__tests__/n044-state-length-sign-spend.
  it 'frames every PUSHDATA length boundary exactly as the on-chain writer does' do
    {
      75 => '4b', 76 => '4c4c', 127 => '4c7f', 128 => '4c80', 129 => '4c81',
      255 => '4cff', 256 => '4d0001', 32_767 => '4dff7f', 32_768 => '4d0080',
      65_535 => '4dffff', 65_536 => '4e00000100'
    }.each do |n, header|
      payload = 'ab' * n
      encoded = encode(payload)
      expect(encoded).to eq(header + payload), "len #{n}: frame header"
      expect(mod.deserialize_state(fields, encoded)).to eq({ 'b' => payload })
    end
  end
end
