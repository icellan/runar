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
        'Point'     => 64,
        # runar-lang's P256Point / P384Point cast constructors hard-assert
        # 64 / 96 bytes and all seven compilers emit them as fixed raw slices;
        # framing them instead deploys a state section 1-2 bytes long and the
        # first spend fails.
        'P256Point' => 64,
        'P384Point' => 96
      }.freeze

      # Wrap hex-encoded data in a Bitcoin Script push data opcode.
      #
      # Uses minimal encoding:
      #   - ≤75 bytes    — direct push (single length byte)
      #   - ≤255 bytes   — OP_PUSHDATA1 (0x4c) + 1-byte length
      #   - ≤65535 bytes — OP_PUSHDATA2 (0x4d) + 2-byte LE length
      #   - otherwise    — OP_PUSHDATA4 (0x4e) + 4-byte LE length
      #
      # Applies BSV consensus rule SCRIPT_VERIFY_MINIMALDATA for single-byte
      # pushes: a 1-byte payload whose value is in {0x01..0x10, 0x81} MUST use
      # the corresponding minimal opcode (OP_1..OP_16 / OP_1NEGATE) rather than
      # the direct push "01 NN". Non-minimal direct pushes are relay-rejected as
      # "Data push larger than necessary".
      #
      # NOTE: 0x00 is deliberately NOT in that set. OP_0 pushes the EMPTY byte
      # array, not a 1-byte 0x00 — so the minimal encoding of a 1-byte 0x00
      # payload is the direct push "01 00" (matching the compiler's
      # encodePushBytesHex in push-encoding.ts), not OP_0 (C9 / S1).
      #
      # @param data_hex [String] hex-encoded bytes to push
      # @return [String] hex-encoded push instruction + data
      def encode_push_data(data_hex)
        data_len = data_hex.length / 2

        # MINIMALDATA: single-byte payloads in the OP_N range must use the
        # corresponding minimal opcode. encode_script_int already
        # short-circuits OP_N for Int fields; this brings the ByteString push
        # path to the same standard so a 1-byte ByteString value does not
        # emit a relay-rejected non-minimal direct push.
        if data_len == 1
          byte = data_hex.to_i(16)
          return format('%02x', 0x50 + byte) if byte.between?(1, 16) # OP_1..OP_16
          return '4f' if byte == 0x81                              # OP_1NEGATE
        end

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
      #   -1        → OP_1NEGATE (0x4f), via encode_push_data's MINIMALDATA rule
      #   otherwise → sign-magnitude little-endian bytes with a minimal push prefix
      #
      # The final push MUST go through encode_push_data rather than emitting a
      # direct "LL <bytes>" prefix inline: the sign-magnitude byte for -1 is
      # 0x81, and a 1-byte 0x81 payload is only minimally encoded as OP_1NEGATE.
      # Emitting '0181' here made Ruby's locking scripts one byte longer than
      # every other SDK's for a -1 constructor arg (shifting OP_CODESEPARATOR
      # positions, so a peer tier's continuation hashOutputs no longer matched
      # and the output could not be spent), and made -1 method args non-relayable
      # under minimal-push enforcement.
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
        encode_push_data(data_hex)
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
      # Fields with a +fixed_array+ annotation are expanded into N element
      # writes (nested arrays flatten recursively) using the declared outer
      # dimensions.  The supplied value for such a field must be a (possibly
      # nested) array matching the declared shape.
      #
      # @param state_fields [Array<StateField>] field descriptors from the artifact
      # @param values [Hash] map of field name → value
      # @return [String] hex-encoded state bytes
      def serialize_state(state_fields, values)
        sorted_fields = state_fields.sort_by(&:index)
        sorted_fields.map do |field|
          if field.respond_to?(:fixed_array) && field.fixed_array
            names = field.fixed_array[:synthetic_names]
            leaf_type = unwrap_fixed_array_leaf(field.type)
            dims = parse_fixed_array_dims(field.type)
            flat = flatten_nested_value(values[field.name], dims)
            raise ArgumentError, "state field '#{field.name}': expected #{names.length} flattened elements, got #{flat.length}" if flat.length != names.length

            flat.each_with_index.map { |v, i| encode_state_value(v, leaf_type, names[i]) }.join
          else
            encode_state_value(values[field.name], field.type, field.name)
          end
        end.join
      end

      # Decode state values from a raw hex string.
      #
      # Fields with a +fixed_array+ annotation are returned as (possibly
      # nested) arrays matching the declared shape, so the caller sees
      # +state["board"] = [0, 1, 2, ...]+ instead of the underlying flat
      # scalar slots.
      #
      # @param state_fields [Array<StateField>] field descriptors from the artifact
      # @param state_hex [String] hex-encoded state bytes (no push opcodes)
      # @return [Hash] map of field name → decoded value
      def deserialize_state(state_fields, state_hex)
        sorted_fields = state_fields.sort_by(&:index)
        result = {}
        offset = 0

        sorted_fields.each do |field|
          if field.respond_to?(:fixed_array) && field.fixed_array
            leaf_type = unwrap_fixed_array_leaf(field.type)
            dims = parse_fixed_array_dims(field.type)
            total = field.fixed_array[:synthetic_names].length
            flat = []
            total.times do
              v, chars_read = decode_state_value(state_hex, offset, leaf_type)
              flat << v
              offset += chars_read
            end
            result[field.name] = regroup_flat_value(flat, dims)
          else
            value, chars_read = decode_state_value(state_hex, offset, field.type)
            result[field.name] = value
            offset += chars_read
          end
        end

        result
      end

      # Parse a nested +FixedArray<...>+ type string into its outer dimensions.
      #
      #   "FixedArray<bigint, 9>"                         → [9]
      #   "FixedArray<FixedArray<bigint, 2>, 3>"          → [3, 2]
      #   "FixedArray<FixedArray<FixedArray<bigint,2>,3>,4>" → [4, 3, 2]
      #
      # Non-FixedArray types return +[]+.
      def parse_fixed_array_dims(type)
        current = type.to_s
        dims = []
        while current.start_with?('FixedArray<')
          inner = current[('FixedArray<'.length)..-2]
          depth = 0
          comma = -1
          inner.each_char.with_index do |ch, idx|
            if ch == '<'
              depth += 1
            elsif ch == '>'
              depth -= 1
            elsif ch == ',' && depth.zero?
              comma = idx
              break
            end
          end
          break if comma == -1

          element_type = inner[0...comma].strip
          length_str = inner[(comma + 1)..].strip
          dims << length_str.to_i
          current = element_type
        end
        dims
      end

      # Strip every +FixedArray<>+ wrapper and return the innermost scalar
      # type string.  +FixedArray<FixedArray<bigint, 2>, 3>+ → +"bigint"+.
      def unwrap_fixed_array_leaf(type)
        current = type.to_s
        while current.start_with?('FixedArray<')
          inner = current[('FixedArray<'.length)..-2]
          depth = 0
          comma = -1
          inner.each_char.with_index do |ch, idx|
            if ch == '<'
              depth += 1
            elsif ch == '>'
              depth -= 1
            elsif ch == ',' && depth.zero?
              comma = idx
              break
            end
          end
          break if comma == -1

          current = inner[0...comma].strip
        end
        current
      end

      # Flatten a (possibly nested) array to a 1-D list matching the declared
      # dimensions.  +dims+ is outermost-first: +[3, 2]+ means a length-3
      # outer array of length-2 inner arrays.
      def flatten_nested_value(value, dims)
        return [] if dims.empty?

        unless value.is_a?(Array)
          raise ArgumentError, "expected an Array for FixedArray state field, got #{value.class}"
        end
        unless value.length == dims[0]
          raise ArgumentError, "expected #{dims[0]} elements, got #{value.length}"
        end

        if dims.length == 1
          value
        else
          rest = dims[1..]
          value.flat_map { |v| flatten_nested_value(v, rest) }
        end
      end

      # Reshape a 1-D list back into a nested array matching +dims+.
      def regroup_flat_value(flat, dims)
        return flat.first if dims.empty?
        return flat if dims.length == 1

        per = flat.length / dims[0]
        (0...dims[0]).map do |i|
          chunk = flat[i * per, per]
          regroup_flat_value(chunk, dims[1..])
        end
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
      # Frame a hex-encoded byte string as a state-section field: <len><data>.
      #
      # Deliberately NOT the MINIMALDATA push encoding used by
      # encode_push_data. The state section is raw data after OP_RETURN in the
      # locking script; the interpreter never executes it, so
      # SCRIPT_VERIFY_MINIMALDATA — a rule applied to push opcodes as they are
      # executed — does not reach it. What does read it is the compiler's
      # on-chain state codec (emitPushDataEncode in
      # packages/runar-compiler/src/passes/05-stack-lower.ts), which writes and
      # parses <len><data>. Both sides must agree byte for byte or the
      # continuation hash check fails and the contract is unspendable.
      #
      # #110 applied the MINIMALDATA short-circuit here, in all seven SDKs and
      # none of the seven compilers, so a 1-byte 0x05 state field serialised
      # off-chain as "55" while the script rebuilt it as "0105".
      # Byte-identical with the other six SDKs.
      #
      # @param data_hex [String] hex-encoded bytes to frame
      # @return [String] hex-encoded length prefix + data
      def encode_push_data_state(data_hex)
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
      private_class_method :encode_push_data_state

      # @param field_type [String] Runar type name
      # @return [String] hex-encoded bytes
      def encode_state_value(value, field_type, label = '?')
        case field_type
        when 'int', 'bigint'
          n = coerce_to_integer(value)
          encode_num2bin(n, 8, label)
        when 'bool', 'boolean'
          value ? '01' : '00'
        else
          hex = value.is_a?(String) ? value : ''
          if TYPE_WIDTHS.key?(field_type)
            # Known fixed-width type — raw hex, no push opcode.
            hex
          else
            # Variable-width type (ByteString, Sig, etc.) — state framing.
            encode_push_data_state(hex)
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
      # Exact inverse of encode_push_data_state, and deliberately as strict as
      # the compiler's on-chain state reader: only <len><data> framing is
      # understood. OP_1..OP_16 (0x51..0x60) and OP_1NEGATE (0x4f) are NOT
      # decoded as single-byte values — accepting them would let the SDK read a
      # state section the contract's own script cannot parse. OP_0 (0x00) falls
      # through to the +opcode <= 75+ branch below and correctly decodes as the
      # empty byte array (0-length push).
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
      # FAILS CLOSED on an out-of-range magnitude. +width+ bytes of
      # sign-magnitude hold +8*width - 1+ magnitude bits — the top bit of the
      # last byte is the sign. The loop below writes the low +width+ bytes and
      # drops everything above, then ORs the sign bit in on top of whatever
      # landed there, so an oversized value used to serialise to a plausible
      # but WRONG word:
      #
      #   2^63      -> 0000000000000080   reads back as 0   (negative zero)
      #   2^63 + 5  -> 0500000000000080   reads back as -5  (sign flip)
      #   2^64      -> 0000000000000000   reads back as 0
      #
      # The deploy then succeeded and the UTXO was unspendable: the covenant
      # rebuilds the continuation with the compiler's own OP_NUM2BIN +width+,
      # which cannot produce those bytes from that number, so
      # +hash256(outputs)+ never matches. Raising here is the only place a
      # runtime-computed state value can be stopped — +±(2^(8*width-1) - 1)+
      # remains representable and is unaffected.
      #
      # @param n     [Integer] the value to encode
      # @param width [Integer] output byte width
      # @param label [String] state field name, for the error message
      # @return [String] hex string of exactly width bytes
      # @raise [ArgumentError] if the magnitude does not fit the state word
      def encode_num2bin(n, width, label = '?')
        limit = 1 << ((8 * width) - 1)
        if n >= limit || n <= -limit
          raise ArgumentError,
                "serialize_state: bigint state field '#{label}' = #{n} does not fit the fixed " \
                "#{width}-byte sign-magnitude state word (magnitude must be < " \
                "2^#{(8 * width) - 1}). Serializing it would write a different number into the " \
                "state section than the contract's on-chain OP_NUM2BIN #{width} rebuilds, " \
                'leaving the output unspendable.'
        end

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
