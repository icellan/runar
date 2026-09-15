# frozen_string_literal: true

# C2 — +deserialize_state+ failed OPEN.
#
# The state blob is read back out of a deployed locking script's OP_RETURN
# tail (RunarContract.from_utxo -> extract_state_from_script ->
# deserialize_state). That script is something any third party can construct,
# so the blob is untrusted input — and the caller then builds and SIGNS a
# continuation output committing to whatever state came back.
#
# Every arm of the Ruby decoder returned a DEFAULT on a short blob and
# advanced the nominal width anyway, desynchronising every later field
# (Ruby's +hex_str[offset, n]+ silently yields a SHORT string rather than
# nil), and +deserialize_state+ had no trailing-byte check at all. Measured
# before the fix, +ruby+ exit 0:
#
#   2a00000000000000            a,b bigint    -> {"a" => 42, "b" => 0}
#   2a.. + 01.. + deadbeef      a,b bigint    -> {"a" => 42, "b" => 1}
#   4b aaaaaa                   m ByteString  -> {"m" => "aaaaaa"}
#   aa x10                      k PubKey      -> {"k" => ""}
#   55                          m ByteString  -> {"m" => ""}
#
# The semantics here are TypeScript's (C28, packages/runar-sdk/src/state.ts,
# test c28-state-strict.test.ts): refuse rather than default, and refuse
# trailing bytes. All seven SDKs read the SAME wire format, so the triggering
# conditions must be identical even though each tier raises its own error
# type.

require 'spec_helper'
require 'runar/sdk'

# rubocop:disable RSpec/DescribeClass
RSpec.describe 'Runar::SDK::State C2 strictness' do
  # rubocop:enable RSpec/DescribeClass

  let(:mod) { Runar::SDK::State }

  def field(name, type, index)
    Runar::SDK::StateField.new(name: name, type: type, index: index)
  end

  let(:two_ints) { [field('a', 'bigint', 0), field('b', 'bigint', 1)] }
  let(:bytestr)  { [field('blob', 'ByteString', 0)] }
  let(:pubkey)   { [field('k', 'PubKey', 0)] }

  # Every fixed-width type and its declared width in bytes.
  fixed_widths = {
    'boolean' => 1, 'bool' => 1, 'bigint' => 8, 'int' => 8,
    'PubKey' => 33, 'Addr' => 20, 'Ripemd160' => 20, 'Sha256' => 32,
    'Point' => 64, 'P256Point' => 64, 'P384Point' => 96
  }

  # -------------------------------------------------------------------------
  # The five hostile blobs from the finding, verbatim.
  # -------------------------------------------------------------------------

  describe 'the five hostile blobs' do
    it 'refuses a truncated trailing bigint' do
      expect { mod.deserialize_state(two_ints, '2a00000000000000') }
        .to raise_error(ArgumentError, /truncat/i)
    end

    it 'refuses trailing bytes' do
      blob = '2a00000000000000' + '0100000000000000' + 'deadbeef'
      expect { mod.deserialize_state(two_ints, blob) }
        .to raise_error(ArgumentError, /trailing/i)
    end

    it 'refuses a push payload that runs past the end' do
      expect { mod.deserialize_state(bytestr, '4baaaaaa') }
        .to raise_error(ArgumentError, /truncat/i)
    end

    it 'refuses a short PubKey' do
      expect { mod.deserialize_state(pubkey, 'aa' * 10) }
        .to raise_error(ArgumentError, /truncat/i)
    end

    it 'refuses a byte that is not a push opcode' do
      expect { mod.deserialize_state(bytestr, '55') }
        .to raise_error(ArgumentError, /is not a push opcode/)
    end
  end

  # -------------------------------------------------------------------------
  # Truncation, exhaustively
  # -------------------------------------------------------------------------

  describe 'truncation' do
    fixed_widths.each do |type, width|
      it "refuses a #{type} one byte short of its #{width}-byte width" do
        expect { mod.deserialize_state([field('v', type, 0)], 'aa' * (width - 1)) }
          .to raise_error(ArgumentError)
      end
    end

    [
      '4c',         # OP_PUSHDATA1, no length byte
      '4c05aabb',   # declares 5 bytes, 2 supplied
      '4d',         # OP_PUSHDATA2, no length bytes
      '4d00',       # half a length
      '4d0500aabb', # declares 5, 2 supplied
      '4e',         # OP_PUSHDATA4, no length bytes
      '4e05000000', # declares 5, none supplied
      '05aabb'      # direct push declares 5, 2 supplied
    ].each do |blob|
      it "bounds-checks push framing #{blob}" do
        expect { mod.deserialize_state(bytestr, blob) }.to raise_error(ArgumentError)
      end
    end

    it 'refuses a missing push opcode byte entirely' do
      fields = [field('n', 'bigint', 0), field('blob', 'ByteString', 1)]
      full = mod.serialize_state(fields, 'n' => 1, 'blob' => 'aa')
      expect { mod.deserialize_state(fields, full[0, 16]) }
        .to raise_error(ArgumentError, /truncat/i)
    end

    it 'refuses a truncated fixed-array element' do
      fields = [Runar::SDK::StateField.new(
        name: 'board', type: 'FixedArray<bigint, 3>', index: 0,
        fixed_array: { synthetic_names: %w[board__0 board__1 board__2], element_type: 'bigint' }
      )]
      full = mod.serialize_state(fields, 'board' => [1, 2, 3])
      expect(full.length).to eq(48)
      expect { mod.deserialize_state(fields, full[0, 40]) }.to raise_error(ArgumentError)
    end

    it 'refuses a blob that is not a whole number of bytes' do
      expect { mod.deserialize_state([field('count', 'bigint', 0)], '00112233445566778') }
        .to raise_error(ArgumentError)
    end
  end

  # -------------------------------------------------------------------------
  # Overlong tails
  # -------------------------------------------------------------------------

  describe 'overlong tails' do
    it 'refuses one unexpected trailing byte' do
      one = [field('a', 'bigint', 0)]
      full = mod.serialize_state(one, 'a' => 42)
      expect { mod.deserialize_state(one, "#{full}ff") }
        .to raise_error(ArgumentError, /trailing/i)
    end

    it 'refuses a trailing byte after a variable-length field' do
      full = mod.serialize_state(bytestr, 'blob' => 'aabbcc')
      expect { mod.deserialize_state(bytestr, "#{full}00") }
        .to raise_error(ArgumentError, /trailing/i)
    end

    it 'refuses a whole extra field' do
      full = mod.serialize_state(two_ints, 'a' => 1, 'b' => 2)
      expect { mod.deserialize_state([field('a', 'bigint', 0)], full) }
        .to raise_error(ArgumentError, /trailing/i)
    end

    it 'surfaces a corrupted continuation through extract_state_from_script' do
      fields = [field('count', 'bigint', 0)]
      artifact = Runar::SDK::RunarArtifact.new(state_fields: fields)
      state_hex = mod.serialize_state(fields, 'count' => 5)
      expect { mod.extract_state_from_script(artifact, "516a#{state_hex}ff") }
        .to raise_error(ArgumentError, /trailing/i)
    end
  end

  # -------------------------------------------------------------------------
  # CONTROLS — a guard that rejects legitimate state is just as broken.
  # -------------------------------------------------------------------------

  describe 'controls: well-formed state still round-trips' do
    it 'round-trips a mixed-type record exactly' do
      fields = [
        field('count', 'bigint', 0),
        field('active', 'boolean', 1),
        field('owner', 'PubKey', 2),
        field('blob', 'ByteString', 3)
      ]
      values = { 'count' => -9, 'active' => true, 'owner' => 'cd' * 33, 'blob' => 'deadbeef' }
      expect(mod.deserialize_state(fields, mod.serialize_state(fields, values))).to eq(values)
    end

    it 'round-trips a 1-byte ByteString in the OP_1..OP_16 value range' do
      hex = mod.serialize_state(bytestr, 'blob' => '05')
      # <len><data>, the compiler's on-chain state codec — NOT the MINIMALDATA
      # opcode form ('55'), which the contract's own script cannot read.
      expect(hex).to eq('0105')
      expect(mod.deserialize_state(bytestr, hex)).to eq('blob' => '05')
    end

    it 'round-trips an empty ByteString' do
      hex = mod.serialize_state(bytestr, 'blob' => '')
      expect(mod.deserialize_state(bytestr, hex)).to eq('blob' => '')
    end

    it 'accepts an empty blob for an empty field list' do
      expect(mod.deserialize_state([], '')).to eq({})
    end

    it 'round-trips a maximal direct push (75 bytes)' do
      payload = 'ab' * 75
      expect(mod.deserialize_state(bytestr, mod.serialize_state(bytestr, 'blob' => payload)))
        .to eq('blob' => payload)
    end

    it 'round-trips an OP_PUSHDATA1-framed payload (76 bytes)' do
      payload = 'ab' * 76
      hex = mod.serialize_state(bytestr, 'blob' => payload)
      expect(hex).to start_with('4c4c')
      expect(mod.deserialize_state(bytestr, hex)).to eq('blob' => payload)
    end

    { 'PubKey' => 33, 'Addr' => 20, 'Ripemd160' => 20, 'Sha256' => 32,
      'Point' => 64, 'P256Point' => 64, 'P384Point' => 96 }.each do |type, width|
      it "round-trips a #{type} at its exact #{width}-byte width" do
        payload = '7e' * width
        expect(mod.deserialize_state([field('v', type, 0)], payload)).to eq('v' => payload)
      end
    end

    it 'round-trips a fixed array' do
      fields = [Runar::SDK::StateField.new(
        name: 'board', type: 'FixedArray<bigint, 3>', index: 0,
        fixed_array: { synthetic_names: %w[board__0 board__1 board__2], element_type: 'bigint' }
      )]
      hex = mod.serialize_state(fields, 'board' => [1, 2, 3])
      expect(mod.deserialize_state(fields, hex)).to eq('board' => [1, 2, 3])
    end

    it 'still restores a legitimate continuation' do
      fields = [field('count', 'bigint', 0)]
      artifact = Runar::SDK::RunarArtifact.new(state_fields: fields)
      state_hex = mod.serialize_state(fields, 'count' => 5)
      expect(mod.extract_state_from_script(artifact, "516a#{state_hex}")).to eq('count' => 5)
    end
  end

  # -------------------------------------------------------------------------
  # Null value for a raw fixed-width field — the four-way byte divergence.
  #
  # Ruby wrote '' (zero bytes for a field the artifact declares N bytes wide),
  # Go '<nil>', Java 'null', TS 'undefined'. None is valid hex; all four deploy
  # a corrupt state section, just differently. Refusing is the only answer that
  # is the same in every tier.
  # -------------------------------------------------------------------------

  describe 'a missing raw fixed-width value' do
    %w[PubKey Addr Ripemd160 Sha256 Point P256Point P384Point].each do |type|
      it "refuses to serialize a missing #{type}" do
        expect { mod.serialize_state([field('v', type, 0)], {}) }
          .to raise_error(ArgumentError, /no value/i)
      end
    end
  end
end
