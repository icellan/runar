# frozen_string_literal: true

require_relative 'state'
require_relative 'types'
require_relative 'errors'

# Script utilities — constructor arg extraction and artifact matching.
#
# Ports the TypeScript SDK's script-utils.ts to Ruby. All methods are
# module-level functions under Runar::SDK::ScriptUtils.

module Runar
  module SDK
    module ScriptUtils
      module_function

      # Require +chars+ hex chars to be available from +offset+, else raise
      # MalformedScriptError (F-238). Mirrors the Java tier's
      # +ScriptUtils.need+ guard — already used for the on-chain
      # state-section reader — applied here to the push-data reader used by
      # constructor-arg extraction and artifact matching.
      def need_hex_chars(hex, offset, chars, what)
        return if offset + chars <= hex.length

        remaining = [hex.length - offset, 0].max
        raise Runar::SDK::MalformedScriptError,
              "read_script_element: truncated script — #{what} runs past the end " \
              "(needs #{chars / 2} byte(s) at hex offset #{offset}, only #{remaining / 2} remain)"
      end

      # Read a single script element (opcode + push data) from a hex string.
      #
      # @param hex [String] full script hex
      # @param offset [Integer] hex-character offset to start reading
      # @return [Hash] { data_hex:, total_hex_chars:, opcode: }
      # @raise [Runar::SDK::MalformedScriptError] (F-238) if the opcode byte
      #   itself, an OP_PUSHDATA1/2/4 length prefix, or the declared push
      #   payload runs past the end of +hex+ — a provider-supplied script is
      #   untrusted input, and a truncated push must never come back as a
      #   short, silently-wrong +data_hex+ (it would also desynchronise every
      #   later slot's offset in the caller's walk).
      def read_script_element(hex, offset)
        need_hex_chars(hex, offset, 2, 'push opcode')
        opcode_str = hex[offset, 2]
        raise Runar::SDK::MalformedScriptError,
              "read_script_element: non-hex byte at hex offset #{offset}" unless opcode_str.match?(/\A[0-9a-fA-F]{2}\z/)

        opcode = opcode_str.to_i(16)

        if opcode == 0x00
          { data_hex: '', total_hex_chars: 2, opcode: opcode }
        elsif opcode >= 0x01 && opcode <= 0x4B
          data_len = opcode * 2
          need_hex_chars(hex, offset, 2 + data_len, 'push payload')
          { data_hex: hex[offset + 2, data_len], total_hex_chars: 2 + data_len, opcode: opcode }
        elsif opcode == 0x4C
          need_hex_chars(hex, offset, 4, 'OP_PUSHDATA1 length prefix')
          len = hex[offset + 2, 2].to_i(16)
          data_len = len * 2
          need_hex_chars(hex, offset, 4 + data_len, 'OP_PUSHDATA1 payload')
          { data_hex: hex[offset + 4, data_len], total_hex_chars: 4 + data_len, opcode: opcode }
        elsif opcode == 0x4D
          need_hex_chars(hex, offset, 6, 'OP_PUSHDATA2 length prefix')
          lo = hex[offset + 2, 2].to_i(16)
          hi = hex[offset + 4, 2].to_i(16)
          len = lo | (hi << 8)
          data_len = len * 2
          need_hex_chars(hex, offset, 6 + data_len, 'OP_PUSHDATA2 payload')
          { data_hex: hex[offset + 6, data_len], total_hex_chars: 6 + data_len, opcode: opcode }
        elsif opcode == 0x4E
          need_hex_chars(hex, offset, 10, 'OP_PUSHDATA4 length prefix')
          b0 = hex[offset + 2, 2].to_i(16)
          b1 = hex[offset + 4, 2].to_i(16)
          b2 = hex[offset + 6, 2].to_i(16)
          b3 = hex[offset + 8, 2].to_i(16)
          len = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
          data_len = len * 2
          need_hex_chars(hex, offset, 10 + data_len, 'OP_PUSHDATA4 payload')
          { data_hex: hex[offset + 10, data_len], total_hex_chars: 10 + data_len, opcode: opcode }
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

        # N-320: one conversion. Shifting a byte in at a time is quadratic: a
        # 1 MiB constructor arg held from_utxo past the CPU budget.
        result = bytes.reverse.pack('C*').unpack1('H*').to_i(16)

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
        # taken from the first occurrence per param. A codeSepIndex slot is a
        # placeholder too: its baked value can be wider than one byte, so it is
        # walked for its width only (param_index -1).
        slots = (artifact.constructor_slots.map { |s| [s.byte_offset, s.param_index] } +
                 Array(artifact.code_sep_index_slots).map { |s| [s.byte_offset, -1] })
                .sort_by(&:first)

        result = {}
        assigned = {}
        cumulative_shift = 0

        slots.each do |byte_offset, param_index|
          adjusted_hex_offset = (byte_offset + cumulative_shift) * 2
          elem = read_script_element(code_hex, adjusted_hex_offset)
          # Template placeholders are exactly 1 byte, so the shift contributed
          # by each occurrence is its encoded width minus that byte.
          cumulative_shift += elem[:total_hex_chars] / 2 - 1
          next if param_index.negative?

          # Deploy only ever writes a push or a small-integer opcode at a
          # constructor slot; any other opcode would otherwise be reported as a
          # value the script does not hold. Checked at every occurrence.
          unless push_opcode?(elem[:opcode])
            raise Runar::SDK::MalformedScriptError,
                  format('extract_constructor_args: opcode 0x%<op>02x at the constructor slot ' \
                         'at template byte %<off>d is not a push', op: elem[:opcode], off: byte_offset)
          end
          next if assigned[param_index]

          assigned[param_index] = true

          params = artifact.abi.constructor_params
          param = param_index < params.length ? params[param_index] : nil
          next unless param

          result[param.name] = interpret_script_element(elem[:opcode], elem[:data_hex], param.type)
        end

        result
      end

      # True when +s+ is an even-length string of hex digits (N-317). \A/\z,
      # not ^/$, so a trailing newline is not accepted.
      def hex_bytes?(s)
        s.length.even? && s.match?(/\A\h*\z/)
      end

      # Determine whether a given on-chain script was produced from the given
      # contract artifact (regardless of what constructor args were used).
      #
      # @param artifact [RunarArtifact] compiled contract artifact
      # @param script_hex [String] hex-encoded on-chain locking script
      # @return [Boolean]
      def matches_artifact(artifact, script_hex)
        # N-317: refuse anything that is not whole bytes of hex up front, so
        # no reader below sees a partial byte and every tier makes the same call.
        unless hex_bytes?(script_hex)
          raise Runar::SDK::MalformedScriptError,
                'matches_artifact: script is not an even-length hex string'
        end

        code_hex = script_hex
        # A stateful contract is deployed with an OP_RETURN and its state after
        # the code part, so a script with no OP_RETURN after it is not a
        # deployment. Only the OP_RETURN's presence is checked, not the state's
        # length.
        missing_state = false
        if artifact.state_fields && !artifact.state_fields.empty?
          op_return_pos = State.find_last_op_return(script_hex)
          if op_return_pos != -1
            code_hex = script_hex[0, op_return_pos]
          else
            missing_state = true
          end
        end

        template = artifact.script

        # N-316: compare literally only when the template has no slot of ANY kind.
        if Array(artifact.constructor_slots).empty? &&
           Array(artifact.code_sep_index_slots).empty? &&
           Array(artifact.code_part_len_slots).empty?
          return code_hex == template && !missing_state
        end

        # Every OP_0 placeholder the SDK replaces at deploy time is one
        # variable script element: constructor slots AND codeSepIndex slots
        # (the latter bake as OP_1, so comparing them literally rejected every
        # honest deployment carrying one; Go/Rust/Python/TS match).
        # De-duplicate by byte_offset.
        slots = (Array(artifact.constructor_slots).map(&:byte_offset) +
                 Array(artifact.code_sep_index_slots).map(&:byte_offset))
                .uniq.sort.map { |off| Struct.new(:byte_offset).new(off) }

        # N-051: a +code_part_len_slots+ field holds the DEPLOYED code-part
        # length, not the template's placeholder value. It must equal the length
        # of the code part being matched (everything before the state section,
        # inscription envelope included).
        len_fields = {}
        Array(artifact.code_part_len_slots).each { |s| len_fields[s.byte_offset * 2] = true }
        deployed_len = [code_hex.length / 2].pack('V').unpack1('H*')
        segment_matches = lambda do |t_start, t_end, c_start|
          t = t_start
          c = c_start
          while t < t_end
            if len_fields[t]
              return false if code_hex[c, 8] != deployed_len

              t += 8
              c += 8
              next
            end
            return false if template[t] != code_hex[c]

            t += 1
            c += 1
          end
          true
        end

        template_pos = 0
        code_pos = 0
        # N-318: the element read at each placeholder, keyed by template byte offset.
        elems = {}

        slots.each do |slot|
          slot_hex_offset = slot.byte_offset * 2
          seg_len = slot_hex_offset - template_pos
          return false if code_pos + seg_len > code_hex.length
          return false unless segment_matches.call(template_pos, slot_hex_offset, code_pos)

          template_pos = slot_hex_offset + 2
          elem_offset = code_pos + seg_len
          elem = read_script_element(code_hex, elem_offset)
          elems[slot.byte_offset] = code_hex[elem_offset, elem[:total_hex_chars]]
          code_pos = elem_offset + elem[:total_hex_chars]
        end

        return false unless code_hex.length - code_pos == template.length - template_pos &&
                            segment_matches.call(template_pos, template.length, code_pos)

        # N-318: a codeSepIndex slot is not free. Deploy bakes exactly
        # encode_script_int(code_sep_index + shift) there, shift = the growth of
        # every constructor slot before code_sep_index plus that of every
        # earlier codeSep slot before it (the TS / Go / Rust / Python / Zig /
        # Java formula). The matcher does not know the constructor args, so
        # their growth is taken from the elements actually read.
        resolved = [] # [byte_offset, width]
        Array(artifact.code_sep_index_slots).sort_by(&:byte_offset).each do |slot|
          shift = 0
          Array(artifact.constructor_slots).each do |cs|
            shift += elems[cs.byte_offset].length / 2 - 1 if cs.byte_offset < slot.code_sep_index
          end
          resolved.each do |prev_offset, prev_width|
            shift += prev_width - 1 if prev_offset < slot.code_sep_index
          end
          expected = State.encode_script_int(slot.code_sep_index + shift)
          return false unless elems[slot.byte_offset] == expected

          resolved << [slot.byte_offset, expected.length / 2]
        end

        # Deploy writes encodeArg(value) at every slot of a param: a push or a
        # small-integer opcode, the same bytes at every occurrence of the
        # param, and exactly fixedValueByteLength bytes where the artifact
        # declares one.
        first_elem = {}
        Array(artifact.constructor_slots).each do |cs|
          el = elems[cs.byte_offset].downcase
          return false unless push_opcode?(el[0, 2].to_i(16))
          return false if !cs.fixed_value_byte_length.nil? && pushed_byte_length(el) != cs.fixed_value_byte_length

          first = first_elem[cs.param_index]
          return false if !first.nil? && first != el

          first_elem[cs.param_index] = el
        end

        # Checked after the slot walk so a malformed script still raises
        # MalformedScriptError (N-317) rather than reporting a plain mismatch.
        return false if missing_state

        true
      end

      # OP_0, a data push, OP_1NEGATE or OP_1..OP_16: what encode_arg can write.
      def push_opcode?(opcode)
        opcode <= 0x4f || (opcode >= 0x51 && opcode <= 0x60)
      end

      # Number of bytes a push element (as sliced by read_script_element)
      # leaves on the stack.
      def pushed_byte_length(element_hex)
        elem = read_script_element(element_hex, 0)
        op = elem[:opcode]
        return 1 if op == 0x4f || (op >= 0x51 && op <= 0x60)

        elem[:data_hex].length / 2
      end
    end

    # Expose ScriptUtils module methods directly on Runar::SDK for convenience.
    extend ScriptUtils
  end
end
