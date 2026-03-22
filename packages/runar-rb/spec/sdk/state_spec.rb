# frozen_string_literal: true

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State' do
  # rubocop:enable RSpec/DescribeClass

  # Convenience alias so examples stay concise.
  let(:mod) { Runar::SDK::State }

  # ---------------------------------------------------------------------------
  # encode_push_data
  # ---------------------------------------------------------------------------

  describe '.encode_push_data' do
    it 'encodes empty data as a single zero byte' do
      expect(mod.encode_push_data('')).to eq('00')
    end

    it 'encodes a 1-byte payload with a direct push (≤75 bytes)' do
      expect(mod.encode_push_data('ab')).to eq('01ab')
    end

    it 'encodes a 75-byte payload without PUSHDATA1' do
      data = 'aa' * 75
      expect(mod.encode_push_data(data)).to eq("4b#{data}")
    end

    it 'encodes a 76-byte payload with OP_PUSHDATA1 (0x4c)' do
      data = 'bb' * 76
      expect(mod.encode_push_data(data)).to eq("4c4c#{data}")
    end

    it 'encodes a 255-byte payload with OP_PUSHDATA1' do
      data = 'cc' * 255
      expect(mod.encode_push_data(data)).to eq("4cff#{data}")
    end

    it 'encodes a 256-byte payload with OP_PUSHDATA2 (0x4d)' do
      data = 'dd' * 256
      # 256 = 0x0100 in little-endian → 0001
      expect(mod.encode_push_data(data)).to eq("4d0001#{data}")
    end

    it 'encodes a 1000-byte payload with OP_PUSHDATA2' do
      data = 'ee' * 1000
      # 1000 = 0x03E8 in little-endian → e803
      expect(mod.encode_push_data(data)).to eq("4de803#{data}")
    end
  end

  # ---------------------------------------------------------------------------
  # encode_script_int
  # ---------------------------------------------------------------------------

  describe '.encode_script_int' do
    it 'encodes 0 as OP_0 (0x00)' do
      expect(mod.encode_script_int(0)).to eq('00')
    end

    it 'encodes 1 as OP_1 (0x51)' do
      expect(mod.encode_script_int(1)).to eq('51')
    end

    it 'encodes 16 as OP_16 (0x60)' do
      expect(mod.encode_script_int(16)).to eq('60')
    end

    it 'encodes 17 as a 1-byte push' do
      # 17 = 0x11, top bit clear, no extra byte needed
      expect(mod.encode_script_int(17)).to eq('0111')
    end

    it 'encodes a small positive value (127)' do
      # 0x7f, top bit clear
      expect(mod.encode_script_int(127)).to eq('017f')
    end

    it 'encodes a value requiring the sign byte (128)' do
      # 0x80 in magnitude → top bit set → append 0x00 sign byte
      expect(mod.encode_script_int(128)).to eq('028000')
    end

    it 'encodes a negative value (-1)' do
      # magnitude 0x01, set top bit → 0x81
      expect(mod.encode_script_int(-1)).to eq('0181')
    end

    it 'encodes -128' do
      # magnitude 0x80 → top bit already set → append 0x80 sign byte
      expect(mod.encode_script_int(-128)).to eq('028080')
    end

    it 'encodes a large positive value (1000)' do
      # 1000 = 0x03E8 LE → e803, top bit clear, no extra byte
      expect(mod.encode_script_int(1000)).to eq('02e803')
    end

    it 'encodes a large negative value (-1000)' do
      # magnitude 1000 = 0x03E8 LE → e803, set top bit on last byte → e883
      expect(mod.encode_script_int(-1000)).to eq('02e883')
    end
  end

  # ---------------------------------------------------------------------------
  # find_last_op_return
  # ---------------------------------------------------------------------------

  describe '.find_last_op_return' do
    it 'returns -1 for an empty script' do
      expect(mod.find_last_op_return('')).to eq(-1)
    end

    it 'returns -1 when no OP_RETURN is present' do
      # OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG
      script = '76a914' + ('aa' * 20) + '88ac'
      expect(mod.find_last_op_return(script)).to eq(-1)
    end

    it 'returns the offset of a bare OP_RETURN at the start' do
      expect(mod.find_last_op_return('6a')).to eq(0)
    end

    it 'returns the correct offset when OP_RETURN follows other opcodes' do
      # OP_NOP (0x61) then OP_RETURN (0x6a)
      script = '616a'
      expect(mod.find_last_op_return(script)).to eq(2)
    end

    it 'does not mistake a 0x6a byte inside push data for OP_RETURN' do
      # Push 1 byte: 0x6a (the length byte 0x01 + data 0x6a)
      # Then real OP_RETURN
      script = '016a6a'
      # offset 0: opcode 0x01 → skip 2 + 2 = 4 chars (offset moves to 4)
      # offset 4: opcode 0x6a → OP_RETURN found at hex offset 4
      expect(mod.find_last_op_return(script)).to eq(4)
    end

    it 'skips OP_PUSHDATA1 content correctly' do
      # OP_PUSHDATA1 (0x4c) length=1 data=0x6a then real OP_RETURN
      script = '4c016a6a'
      # offset 0: opcode 0x4c, push_len=1 → skip 4 + 2 = 6 chars (offset 6)
      # offset 6: opcode 0x6a → OP_RETURN at hex offset 6
      expect(mod.find_last_op_return(script)).to eq(6)
    end

    it 'skips OP_PUSHDATA2 content correctly' do
      # OP_PUSHDATA2 (0x4d) length=0x0002 LE (2 bytes of data=0x6a6a) then OP_RETURN
      script = '4d02006a6a6a'
      # offset 0: opcode 0x4d, lo=0x02 hi=0x00 → push_len=2 → skip 6 + 4 = 10 chars
      # offset 10: opcode 0x6a → OP_RETURN at hex offset 10
      expect(mod.find_last_op_return(script)).to eq(10)
    end
  end

  # ---------------------------------------------------------------------------
  # serialize_state + deserialize_state round-trips
  # ---------------------------------------------------------------------------

  describe '.serialize_state and .deserialize_state' do
    def make_field(name, type, index)
      Runar::SDK::StateField.new(name: name, type: type, index: index)
    end

    context 'with a bigint field' do
      let(:fields) { [make_field('count', 'bigint', 0)] }

      it 'round-trips zero' do
        hex    = mod.serialize_state(fields, { 'count' => 0 })
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(0)
      end

      it 'round-trips a positive integer' do
        hex    = mod.serialize_state(fields, { 'count' => 42 })
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(42)
      end

      it 'round-trips a negative integer' do
        hex    = mod.serialize_state(fields, { 'count' => -99 })
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(-99)
      end

      it 'round-trips a large positive integer' do
        hex    = mod.serialize_state(fields, { 'count' => 1_000_000 })
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(1_000_000)
      end

      it 'accepts BigInt-style strings ending in "n"' do
        hex    = mod.serialize_state(fields, { 'count' => '7n' })
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(7)
      end

      it 'encodes as exactly 16 hex chars (8 bytes)' do
        hex = mod.serialize_state(fields, { 'count' => 1 })
        expect(hex.length).to eq(16)
      end
    end

    context 'with a boolean field' do
      let(:fields) { [make_field('active', 'bool', 0)] }

      it 'round-trips true' do
        hex    = mod.serialize_state(fields, { 'active' => true })
        result = mod.deserialize_state(fields, hex)
        expect(result['active']).to be true
      end

      it 'round-trips false' do
        hex    = mod.serialize_state(fields, { 'active' => false })
        result = mod.deserialize_state(fields, hex)
        expect(result['active']).to be false
      end

      it 'encodes true as "01"' do
        expect(mod.serialize_state(fields, { 'active' => true })).to eq('01')
      end

      it 'encodes false as "00"' do
        expect(mod.serialize_state(fields, { 'active' => false })).to eq('00')
      end
    end

    context 'with a ByteString field' do
      let(:fields) { [make_field('data', 'ByteString', 0)] }

      it 'round-trips a hex string unchanged' do
        raw = 'deadbeef'
        hex    = mod.serialize_state(fields, { 'data' => raw })
        result = mod.deserialize_state(fields, hex)
        # ByteString is variable-width, stored with push-data prefix.
        expect(hex).to eq(mod.encode_push_data(raw))
        expect(result['data']).to eq(raw)
      end
    end

    context 'with a PubKey field (33 bytes, fixed width)' do
      let(:fields) { [make_field('owner', 'PubKey', 0)] }
      let(:pub_key_hex) { '02' + ('ab' * 32) }

      it 'round-trips the public key bytes' do
        hex    = mod.serialize_state(fields, { 'owner' => pub_key_hex })
        result = mod.deserialize_state(fields, hex)
        expect(hex).to eq(pub_key_hex)
        expect(result['owner']).to eq(pub_key_hex)
      end
    end

    context 'with multiple fields in non-index order' do
      let(:fields) do
        [
          make_field('name', 'PubKey', 1),
          make_field('count', 'bigint', 0)
        ]
      end
      let(:pub_key_hex) { '03' + ('cd' * 32) }

      it 'sorts by index and round-trips correctly' do
        values = { 'count' => 5, 'name' => pub_key_hex }
        hex    = mod.serialize_state(fields, values)
        result = mod.deserialize_state(fields, hex)
        expect(result['count']).to eq(5)
        expect(result['name']).to eq(pub_key_hex)
      end
    end
  end

  # ---------------------------------------------------------------------------
  # extract_state_from_script
  # ---------------------------------------------------------------------------

  describe '.extract_state_from_script' do
    def make_field(name, type, index)
      Runar::SDK::StateField.new(name: name, type: type, index: index)
    end

    def make_artifact(state_fields)
      Runar::SDK::RunarArtifact.new(state_fields: state_fields)
    end

    it 'returns nil when the artifact has no state fields' do
      artifact = make_artifact([])
      expect(mod.extract_state_from_script(artifact, '6a0000000000000000')).to be_nil
    end

    it 'returns nil when no OP_RETURN is present' do
      field    = make_field('count', 'bigint', 0)
      artifact = make_artifact([field])
      script   = '76a914' + ('aa' * 20) + '88ac'
      expect(mod.extract_state_from_script(artifact, script)).to be_nil
    end

    it 'decodes state from a realistic stateful locking script' do
      field    = make_field('count', 'bigint', 0)
      artifact = make_artifact([field])

      # Build a minimal script: some opcodes, then OP_RETURN, then state bytes.
      # OP_DUP (0x76) + OP_RETURN (0x6a) + count=42 encoded as 8-byte NUM2BIN
      count_hex  = '2a00000000000000' # 42 in 8-byte LE sign-magnitude
      script_hex = "766a#{count_hex}"

      result = mod.extract_state_from_script(artifact, script_hex)
      expect(result).not_to be_nil
      expect(result['count']).to eq(42)
    end

    it 'handles multiple state fields after OP_RETURN' do
      fields = [
        make_field('count', 'bigint', 0),
        make_field('active', 'bool', 1)
      ]
      artifact = make_artifact(fields)

      count_hex  = '0100000000000000' # 1 in 8-byte LE
      active_hex = '01'               # true
      script_hex = "6a#{count_hex}#{active_hex}"

      result = mod.extract_state_from_script(artifact, script_hex)
      expect(result['count']).to eq(1)
      expect(result['active']).to be true
    end
  end
end
