# frozen_string_literal: true

# State serialisation — encode/decode contract state as Bitcoin Script push data.
#
# State values are stored after an OP_RETURN separator in the locking script.
# Integers use fixed-width 8-byte little-endian sign-magnitude (NUM2BIN format).
# Booleans use a single raw byte: 0x00 for false, 0x01 for true.
# ByteString-like types (PubKey, Sig, Addr, etc.) are stored as raw hex bytes.
#
# The public helpers encode_push_data and encode_script_int are also provided
# for callers that need to hand-craft push operations outside of state encoding.

module Runar
  module SDK
    module State
      module_function

      # Fixed byte widths for known fixed-size types.
      TYPE_WIDTHS = {
        'PubKey'    => 33,
        'Addr'      => 20,
        'Ripemd160' => 20,
        'Sha256'    => 32,
        'Point'     => 64
      }.freeze

      # Wrap hex-encoded data in a Bitcoin Script push data opcode.
      #
      # Uses minimal encoding:
      #   - ≤75 bytes    — direct push (single length byte)
      #   - ≤255 bytes   — OP_PUSHDATA1 (0x4c) + 1-byte length
      #   - ≤65535 bytes — OP_PUSHDATA2 (0x4d) + 2-byte LE length
      #   - otherwise    — OP_PUSHDATA4 (0x4e) + 4-byte LE length
      #
      # @param data_hex [String] hex-encoded bytes to push
      # @return [String] hex-encoded push instruction + data
      def encode_push_data(data_hex)
        data_len = data_hex.length / 2

        if data_len <= 75
          format('%02x', data_len) + data_hex
        elsif data_len <= 0xFF
          '4c' + format('%02x', data_len) + data_hex
        elsif data_len <= 0xFFFF
          '4d' + [data_len].pack('v').unpack1('H*') + data_hex
        else
          '4e' + [data_len].pack('V').unpack1('H*') + data_hex
        end
      end

      # Encode an integer as a minimally-encoded Bitcoin Script number push.
      #
      # Special cases:
      #   0         → OP_0  (0x00)
      #   1–16      → OP_1–OP_16 (0x51–0x60)
      #   otherwise → sign-magnitude little-endian bytes with a direct push prefix
      #
      # @param n [Integer] the integer to encode
      # @return [String] hex-encoded push opcode + (optional) data
      def encode_script_int(n)
        return '00' if n.zero?

        if n >= 1 && n <= 16
          return format('%02x', 0x50 + n)
        end

        # Sign-magnitude little-endian encoding.
        negative = n.negative?
        abs_val  = n.abs
        bytes    = []

        while abs_val.positive?
          bytes << (abs_val & 0xFF)
          abs_val >>= 8
        end

        # If the top bit of the last byte is set, append an extra byte to hold
        # the sign flag without ambiguity.
        if (bytes.last & 0x80).nonzero?
          bytes << (negative ? 0x80 : 0x00)
        elsif negative
          bytes[-1] |= 0x80
        end

        data_hex = bytes.map { |b| format('%02x', b) }.join
        format('%02x', bytes.length) + data_hex
      end

      # Find the hex-char offset of the last OP_RETURN (0x6a) at a real opcode
      # boundary.
      #
      # Walks opcodes correctly so that 0x6a bytes embedded inside push data are
      # not mistaken for OP_RETURN.  In practice a Runar stateful contract has
      # exactly one OP_RETURN; the walk stops immediately when it finds it.
      #
      # @param script_hex [String] full locking script as a hex string
      # @return [Integer] hex-char offset of OP_RETURN, or -1 if not found
      def find_last_op_return(script_hex)
        last_pos = -1
        offset   = 0
        length   = script_hex.length

        while offset + 2 <= length
          opcode = script_hex[offset, 2].to_i(16)

          if opcode == 0x6A
            # OP_RETURN at a real opcode boundary. Everything after is raw state
            # data, so stop walking immediately.
            return offset
          elsif opcode >= 0x01 && opcode <= 0x4B
            offset += 2 + opcode * 2
          elsif opcode == 0x4C
            break if offset + 4 > length

            push_len = script_hex[offset + 2, 2].to_i(16)
            offset += 4 + push_len * 2
          elsif opcode == 0x4D
            break if offset + 6 > length

            lo       = script_hex[offset + 2, 2].to_i(16)
            hi       = script_hex[offset + 4, 2].to_i(16)
            push_len = lo | (hi << 8)
            offset += 6 + push_len * 2
          elsif opcode == 0x4E
            break if offset + 10 > length

            push_len = [script_hex[offset + 2, 8]].pack('H*').unpack1('V')
            offset += 10 + push_len * 2
          else
            offset += 2
          end
        end

        last_pos
      end

      # Encode a list of state field values into a raw hex string.
      #
      # Fields are sorted by their index before encoding so the order always
      # matches what the compiler emits.  No push opcodes are added; the result
      # is raw bytes suitable for appending after OP_RETURN.
      #
      # @param state_fields [Array<StateField>] field descriptors from the artifact
      # @param values [Hash] map of field name → value
      # @return [String] hex-encoded state bytes
      def serialize_state(state_fields, values)
        sorted_fields = state_fields.sort_by(&:index)
        sorted_fields.map { |field| encode_state_value(values[field.name], field.type) }.join
      end

      # Decode state values from a raw hex string.
      #
      # @param state_fields [Array<StateField>] field descriptors from the artifact
      # @param state_hex [String] hex-encoded state bytes (no push opcodes)
      # @return [Hash] map of field name → decoded value
      def deserialize_state(state_fields, state_hex)
        sorted_fields = state_fields.sort_by(&:index)
        result = {}
        offset = 0

        sorted_fields.each do |field|
          value, chars_read = decode_state_value(state_hex, offset, field.type)
          result[field.name] = value
          offset += chars_read
        end

        result
      end

      # Extract and decode state from a full locking script.
      #
      # Locates the OP_RETURN separator, then decodes everything after it as
      # raw state bytes.
      #
      # @param artifact [RunarArtifact] compiled contract artifact
      # @param full_locking_script_hex [String] complete locking script as hex
      # @return [Hash, nil] decoded state hash, or nil if no OP_RETURN / no state fields
      def extract_state_from_script(artifact, full_locking_script_hex)
        return nil if artifact.state_fields.nil? || artifact.state_fields.empty?

        op_return_pos = find_last_op_return(full_locking_script_hex)
        return nil if op_return_pos == -1

        # Skip past the OP_RETURN byte (2 hex chars) to reach raw state data.
        state_hex = full_locking_script_hex[op_return_pos + 2..]
        deserialize_state(artifact.state_fields, state_hex)
      end

      # ---------------------------------------------------------------------------
      # Private helpers
      # ---------------------------------------------------------------------------

      # Encode a single state value to raw hex bytes (no push opcode wrapper).
      #
      # @param value  the Ruby value to encode
      # @param field_type [String] Runar type name
      # @return [String] hex-encoded bytes
      def encode_state_value(value, field_type)
        case field_type
        when 'int', 'bigint'
          n = coerce_to_integer(value)
          encode_num2bin(n, 8)
        when 'bool', 'boolean'
          value ? '01' : '00'
        else
          hex = value.is_a?(String) ? value : ''
          if TYPE_WIDTHS.key?(field_type)
            # Known fixed-width type — raw hex, no push opcode.
            hex
          else
            # Variable-width type (ByteString, Sig, etc.) — push-data encoded.
            encode_push_data(hex)
          end
        end
      end
      private_class_method :encode_state_value

      # Decode a single state value from a hex string at the given offset.
      #
      # @param hex_str [String] hex-encoded state bytes
      # @param offset  [Integer] current hex-char offset
      # @param field_type [String] Runar type name
      # @return [Array(Object, Integer)] [decoded_value, hex_chars_consumed]
      def decode_state_value(hex_str, offset, field_type)
        case field_type
        when 'bool', 'boolean'
          return [false, 2] if offset + 2 > hex_str.length

          byte = hex_str[offset, 2]
          [byte != '00', 2]
        when 'int', 'bigint'
          hex_width = 16 # 8 bytes × 2 hex chars
          return [0, hex_width] if offset + hex_width > hex_str.length

          data = hex_str[offset, hex_width]
          [decode_num2bin(data), hex_width]
        else
          width = TYPE_WIDTHS[field_type]
          if width
            hex_chars = width * 2
            data = offset + hex_chars <= hex_str.length ? hex_str[offset, hex_chars] : ''
            [data, hex_chars]
          else
            # Unknown type: fall back to push-data decoding.
            decode_push_data(hex_str, offset)
          end
        end
      end
      private_class_method :decode_state_value

      # Decode a push-data item from hex_str at the given offset.
      #
      # @param hex_str [String]
      # @param offset  [Integer]
      # @return [Array(String, Integer)] [data_hex, hex_chars_consumed]
      def decode_push_data(hex_str, offset)
        return ['', 0] if offset >= hex_str.length

        opcode = hex_str[offset, 2].to_i(16)

        if opcode <= 75
          data_len = opcode * 2
          [hex_str[offset + 2, data_len] || '', 2 + data_len]
        elsif opcode == 0x4C
          length   = hex_str[offset + 2, 2].to_i(16)
          data_len = length * 2
          [hex_str[offset + 4, data_len] || '', 4 + data_len]
        elsif opcode == 0x4D
          lo       = hex_str[offset + 2, 2].to_i(16)
          hi       = hex_str[offset + 4, 2].to_i(16)
          length   = lo | (hi << 8)
          data_len = length * 2
          [hex_str[offset + 6, data_len] || '', 6 + data_len]
        elsif opcode == 0x4E
          length   = [hex_str[offset + 2, 8]].pack('H*').unpack1('V')
          data_len = length * 2
          [hex_str[offset + 10, data_len] || '', 10 + data_len]
        else
          ['', 2]
        end
      end
      private_class_method :decode_push_data

      # Encode an integer as fixed-width little-endian sign-magnitude bytes
      # (Bitcoin's NUM2BIN format).
      #
      # @param n     [Integer] the value to encode
      # @param width [Integer] output byte width
      # @return [String] hex string of exactly width bytes
      def encode_num2bin(n, width)
        negative = n.negative?
        abs_val  = n.abs
        result   = Array.new(width, 0)

        width.times do |i|
          break if abs_val.zero?

          result[i] = abs_val & 0xFF
          abs_val >>= 8
        end

        result[width - 1] |= 0x80 if negative

        result.map { |b| format('%02x', b) }.join
      end
      private_class_method :encode_num2bin

      # Decode a fixed-width little-endian sign-magnitude number.
      #
      # @param hex_str [String] exactly width*2 hex chars
      # @return [Integer]
      def decode_num2bin(hex_str)
        return 0 if hex_str.nil? || hex_str.empty?

        bytes    = [hex_str].pack('H*').bytes
        negative = (bytes.last & 0x80) != 0
        bytes[-1] &= 0x7F

        result = 0
        bytes.reverse_each { |b| result = (result << 8) | b }

        return 0 if result.zero?

        negative ? -result : result
      end
      private_class_method :decode_num2bin

      # Coerce a value from JSON or Ruby into an Integer.
      #
      # Handles:
      #   nil         → 0
      #   "42n"       → 42  (BigInt string from JSON without reviver)
      #   Integer     → as-is
      #   other       → Integer() conversion
      def coerce_to_integer(value)
        return 0 if value.nil?
        return value.to_s.chomp('n').to_i if value.is_a?(String) && value.end_with?('n')

        Integer(value)
      end
      private_class_method :coerce_to_integer
    end

    # Expose State module methods directly on Runar::SDK for convenience,
    # matching the flat function API in the Python SDK.
    extend State
  end
end
