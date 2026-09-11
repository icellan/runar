# frozen_string_literal: true

require_relative 'state'
require_relative 'types'

# Script utilities — constructor arg extraction and artifact matching.
#
# Ports the TypeScript SDK's script-utils.ts to Ruby. All methods are
# module-level functions under Runar::SDK::ScriptUtils.

module Runar
  module SDK
    module ScriptUtils
      module_function

      # Read a single script element (opcode + push data) from a hex string.
      #
      # @param hex [String] full script hex
      # @param offset [Integer] hex-character offset to start reading
      # @return [Hash] { data_hex:, total_hex_chars:, opcode: }
      def read_script_element(hex, offset)
        opcode = hex[offset, 2].to_i(16)

        if opcode == 0x00
          { data_hex: '', total_hex_chars: 2, opcode: opcode }
        elsif opcode >= 0x01 && opcode <= 0x4B
          data_len = opcode * 2
          { data_hex: hex[offset + 2, data_len] || '', total_hex_chars: 2 + data_len, opcode: opcode }
        elsif opcode == 0x4C
          len = hex[offset + 2, 2].to_i(16)
          data_len = len * 2
          { data_hex: hex[offset + 4, data_len] || '', total_hex_chars: 4 + data_len, opcode: opcode }
        elsif opcode == 0x4D
          lo = hex[offset + 2, 2].to_i(16)
          hi = hex[offset + 4, 2].to_i(16)
          len = lo | (hi << 8)
          data_len = len * 2
          { data_hex: hex[offset + 6, data_len] || '', total_hex_chars: 6 + data_len, opcode: opcode }
        elsif opcode == 0x4E
          b0 = hex[offset + 2, 2].to_i(16)
          b1 = hex[offset + 4, 2].to_i(16)
          b2 = hex[offset + 6, 2].to_i(16)
          b3 = hex[offset + 8, 2].to_i(16)
          len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
          data_len = len * 2
          { data_hex: hex[offset + 10, data_len] || '', total_hex_chars: 10 + data_len, opcode: opcode }
        else
          { data_hex: '', total_hex_chars: 2, opcode: opcode }
        end
      end

      # Decode a script number from a hex-encoded little-endian sign-magnitude byte sequence.
      #
      # @param data_hex [String] hex-encoded bytes
      # @return [Integer]
      def decode_script_number(data_hex)
        return 0 if data_hex.nil? || data_hex.empty?

        bytes = [data_hex].pack('H*').bytes
        negative = (bytes.last & 0x80) != 0
        bytes[-1] &= 0x7F

        result = 0
        bytes.reverse_each { |b| result = (result << 8) | b }

        return 0 if result.zero?

        negative ? -result : result
      end

      # Interpret a script element according to its Runar type.
      #
      # @param opcode [Integer] the opcode byte
      # @param data_hex [String] hex-encoded push data
      # @param type [String] Runar type name ('int', 'bigint', 'bool', etc.)
      # @return [Object] decoded value
      # How a constructor-slot value of a given ABI type is encoded in the
      # script. TABLE, not a hand-maintained +when+ list: the two spellings
      # missing from the old case — the +bigint+ aliases +RabinSig+ /
      # +RabinPubKey+, and the CANONICAL +boolean+ (only the +bool+ alias was
      # handled) — each silently turned a value into a hex string on the way
      # back off chain. Mirrors
      # packages/runar-ir-schema/src/abi-type-encoding.ts, the same table the
      # compiler stamps +ConstructorSlot#valueEncoding+ from.
      ABI_VALUE_ENCODINGS = {
        'bigint' => :scriptnum,
        'int' => :scriptnum,
        # RabinSig / RabinPubKey are bigint aliases; verifyRabinSig lowers to
        # OP_MOD, which reads its operand as a little-endian sign-magnitude
        # Script number — exactly what bigint gets.
        'RabinSig' => :scriptnum,
        'RabinPubKey' => :scriptnum,
        # 'boolean' is canonical; 'bool' is the alias several frontends spell.
        'boolean' => :bool,
        'bool' => :bool
      }.freeze

      # Classify an ABI type name. ByteString and every fixed-width byte type
      # fall through to :data (a raw push).
      def abi_value_encoding(type)
        ABI_VALUE_ENCODINGS.fetch(type, :data)
      end

      def interpret_script_element(opcode, data_hex, type)
        case abi_value_encoding(type)
        when :scriptnum
          return 0 if opcode == 0x00
          return opcode - 0x50 if opcode >= 0x51 && opcode <= 0x60
          return -1 if opcode == 0x4F

          decode_script_number(data_hex)
        when :bool
          return false if opcode == 0x00
          return true if opcode == 0x51

          data_hex != '00'
        else
          # S1: a ByteString (or other non-numeric) ctor arg whose 1-byte value
          # was MINIMALDATA-encoded as OP_1..OP_16 / OP_1NEGATE carries no
          # separate data bytes in the script — +read_script_element+ reports an
          # empty +data_hex+ for these opcodes (they aren't direct pushes or
          # OP_PUSHDATA*). The opcode itself IS the value; reconstruct it instead
          # of forwarding the (empty) data_hex. OP_0 correctly falls through to
          # +data_hex+ (the empty string), matching OP_0's true semantics
          # (pushes [], not a 1-byte 0x00).
          return format('%02x', opcode - 0x50) if opcode >= 0x51 && opcode <= 0x60
          return '81' if opcode == 0x4F

          data_hex
        end
      end

      # Extract constructor argument values from a compiled on-chain script.
      #
      # Uses +artifact.constructor_slots+ to locate each constructor arg at its
      # byte offset, reads the push data, and deserializes according to the
      # ABI param type.
      #
      # @param artifact [RunarArtifact] compiled contract artifact
      # @param script_hex [String] hex-encoded on-chain locking script
      # @return [Hash] map of param name to decoded value
      def extract_constructor_args(artifact, script_hex)
        return {} if artifact.constructor_slots.nil? || artifact.constructor_slots.empty?

        code_hex = script_hex
        if artifact.state_fields && !artifact.state_fields.empty?
          op_return_pos = State.find_last_op_return(script_hex)
          code_hex = script_hex[0, op_return_pos] if op_return_pos != -1
        end

        # Walk EVERY slot in byte order. A constructor param referenced more
        # than once in the contract body emits one slot per reference, and each
        # occurrence's encoded width contributes to the cumulative offset shift
        # — deduplicating before the walk drops those widths and mis-aligns
        # every later slot on artifacts with repeated references. The VALUE is
        # taken from the first occurrence per param.
        slots = artifact.constructor_slots.sort_by(&:byte_offset)

        result = {}
        assigned = {}
        cumulative_shift = 0

        slots.each do |slot|
          adjusted_hex_offset = (slot.byte_offset + cumulative_shift) * 2
          elem = read_script_element(code_hex, adjusted_hex_offset)
          # Template placeholders are exactly 1 byte, so the shift contributed
          # by each occurrence is its encoded width minus that byte.
          cumulative_shift += elem[:total_hex_chars] / 2 - 1
          next if assigned[slot.param_index]

          assigned[slot.param_index] = true

          params = artifact.abi.constructor_params
          param = slot.param_index < params.length ? params[slot.param_index] : nil
          next unless param

          result[param.name] = interpret_script_element(elem[:opcode], elem[:data_hex], param.type)
        end

        result
      end

      # Determine whether a given on-chain script was produced from the given
      # contract artifact (regardless of what constructor args were used).
      #
      # @param artifact [RunarArtifact] compiled contract artifact
      # @param script_hex [String] hex-encoded on-chain locking script
      # @return [Boolean]
      def matches_artifact(artifact, script_hex)
        code_hex = script_hex
        if artifact.state_fields && !artifact.state_fields.empty?
          op_return_pos = State.find_last_op_return(script_hex)
          code_hex = script_hex[0, op_return_pos] if op_return_pos != -1
        end

        template = artifact.script

        if artifact.constructor_slots.nil? || artifact.constructor_slots.empty?
          return code_hex == template
        end

        # De-duplicate by byte_offset.
        seen_offsets = {}
        slots = artifact.constructor_slots
                        .sort_by(&:byte_offset)
                        .select { |s| seen_offsets[s.byte_offset] ? false : (seen_offsets[s.byte_offset] = true) }

        template_pos = 0
        code_pos = 0

        slots.each do |slot|
          slot_hex_offset = slot.byte_offset * 2
          template_segment = template[template_pos...slot_hex_offset]
          code_segment = code_hex[code_pos, template_segment.length]
          return false if template_segment != code_segment

          template_pos = slot_hex_offset + 2
          elem_offset = code_pos + template_segment.length
          elem = read_script_element(code_hex, elem_offset)
          code_pos = elem_offset + elem[:total_hex_chars]
        end

        template[template_pos..] == code_hex[code_pos..]
      end
    end

    # Expose ScriptUtils module methods directly on Runar::SDK for convenience.
    extend ScriptUtils
  end
end
