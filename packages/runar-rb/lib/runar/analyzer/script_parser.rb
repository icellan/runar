# frozen_string_literal: true

module Runar
  module Analyzer
    # Bitcoin Script byte-level parser. Produces a list of opcode records.
    # Each record is a Hash with keys: :offset, :opcode, :name, :size,
    # plus :push_encoding and :data_length for push operations.
    module ScriptParser
      OPCODE_NAMES = {
        0x00 => 'OP_0',
        0x4c => 'OP_PUSHDATA1',
        0x4d => 'OP_PUSHDATA2',
        0x4e => 'OP_PUSHDATA4',
        0x4f => 'OP_1NEGATE',
        0x51 => 'OP_1',
        0x52 => 'OP_2',
        0x53 => 'OP_3',
        0x54 => 'OP_4',
        0x55 => 'OP_5',
        0x56 => 'OP_6',
        0x57 => 'OP_7',
        0x58 => 'OP_8',
        0x59 => 'OP_9',
        0x5a => 'OP_10',
        0x5b => 'OP_11',
        0x5c => 'OP_12',
        0x5d => 'OP_13',
        0x5e => 'OP_14',
        0x5f => 'OP_15',
        0x60 => 'OP_16',
        0x61 => 'OP_NOP',
        0x63 => 'OP_IF',
        0x64 => 'OP_NOTIF',
        0x67 => 'OP_ELSE',
        0x68 => 'OP_ENDIF',
        0x69 => 'OP_VERIFY',
        0x6a => 'OP_RETURN',
        0x6b => 'OP_TOALTSTACK',
        0x6c => 'OP_FROMALTSTACK',
        0x6d => 'OP_2DROP',
        0x6e => 'OP_2DUP',
        0x6f => 'OP_3DUP',
        0x70 => 'OP_2OVER',
        0x71 => 'OP_2ROT',
        0x72 => 'OP_2SWAP',
        0x73 => 'OP_IFDUP',
        0x74 => 'OP_DEPTH',
        0x75 => 'OP_DROP',
        0x76 => 'OP_DUP',
        0x77 => 'OP_NIP',
        0x78 => 'OP_OVER',
        0x79 => 'OP_PICK',
        0x7a => 'OP_ROLL',
        0x7b => 'OP_ROT',
        0x7c => 'OP_SWAP',
        0x7d => 'OP_TUCK',
        0x7e => 'OP_CAT',
        0x7f => 'OP_SPLIT',
        0x80 => 'OP_NUM2BIN',
        0x81 => 'OP_BIN2NUM',
        0x82 => 'OP_SIZE',
        0x83 => 'OP_INVERT',
        0x84 => 'OP_AND',
        0x85 => 'OP_OR',
        0x86 => 'OP_XOR',
        0x87 => 'OP_EQUAL',
        0x88 => 'OP_EQUALVERIFY',
        0x8b => 'OP_1ADD',
        0x8c => 'OP_1SUB',
        0x8f => 'OP_NEGATE',
        0x90 => 'OP_ABS',
        0x91 => 'OP_NOT',
        0x92 => 'OP_0NOTEQUAL',
        0x93 => 'OP_ADD',
        0x94 => 'OP_SUB',
        0x95 => 'OP_MUL',
        0x96 => 'OP_DIV',
        0x97 => 'OP_MOD',
        0x98 => 'OP_LSHIFT',
        0x99 => 'OP_RSHIFT',
        0x9a => 'OP_BOOLAND',
        0x9b => 'OP_BOOLOR',
        0x9c => 'OP_NUMEQUAL',
        0x9d => 'OP_NUMEQUALVERIFY',
        0x9e => 'OP_NUMNOTEQUAL',
        0x9f => 'OP_LESSTHAN',
        0xa0 => 'OP_GREATERTHAN',
        0xa1 => 'OP_LESSTHANOREQUAL',
        0xa2 => 'OP_GREATERTHANOREQUAL',
        0xa3 => 'OP_MIN',
        0xa4 => 'OP_MAX',
        0xa5 => 'OP_WITHIN',
        0xa6 => 'OP_RIPEMD160',
        0xa7 => 'OP_SHA1',
        0xa8 => 'OP_SHA256',
        0xa9 => 'OP_HASH160',
        0xaa => 'OP_HASH256',
        0xab => 'OP_CODESEPARATOR',
        0xac => 'OP_CHECKSIG',
        0xad => 'OP_CHECKSIGVERIFY',
        0xae => 'OP_CHECKMULTISIG',
        0xaf => 'OP_CHECKMULTISIGVERIFY'
      }.freeze

      # Return the canonical opcode name string per spec §4.
      def self.opcode_name(byte, push_encoding: nil, data_length: nil)
        return 'OP_0' if byte == 0x00
        return 'OP_1' if byte == 0x51
        if push_encoding == :direct
          return "PUSH_#{data_length}"
        end
        name = OPCODE_NAMES[byte]
        return name if name
        format('OP_UNKNOWN(0x%02x)', byte)
      end

      # Parse the hex string into a list of opcode records.
      # Truncated pushes are silently retained with whatever data was
      # available. Returns Array of Hashes.
      def self.parse(hex)
        # Decode hex into byte array.
        bytes = []
        i = 0
        len = hex.length
        while i + 1 < len
          bytes << hex[i, 2].to_i(16)
          i += 2
        end

        ops = []
        idx = 0
        n = bytes.length
        while idx < n
          op = bytes[idx]
          offset = idx

          if op >= 0x01 && op <= 0x4b
            data_len = op
            available = [data_len, n - (idx + 1)].min
            size = 1 + available
            ops << {
              offset: offset,
              opcode: op,
              name: "PUSH_#{data_len}",
              size: size,
              push_encoding: :direct,
              data_length: data_len
            }
            idx += size
            # If truncated (available < data_len), the script ends here.
            break if available < data_len
          elsif op == 0x4c
            # OP_PUSHDATA1: 1 byte length
            if idx + 1 >= n
              # Truncated header
              ops << {
                offset: offset,
                opcode: op,
                name: 'OP_PUSHDATA1',
                size: n - idx,
                push_encoding: :pushdata1,
                data_length: 0
              }
              break
            end
            data_len = bytes[idx + 1]
            available = [data_len, n - (idx + 2)].min
            size = 2 + available
            ops << {
              offset: offset,
              opcode: op,
              name: 'OP_PUSHDATA1',
              size: size,
              push_encoding: :pushdata1,
              data_length: data_len
            }
            idx += size
            break if available < data_len
          elsif op == 0x4d
            # OP_PUSHDATA2: 2 byte LE length
            if idx + 2 >= n
              ops << {
                offset: offset,
                opcode: op,
                name: 'OP_PUSHDATA2',
                size: n - idx,
                push_encoding: :pushdata2,
                data_length: 0
              }
              break
            end
            data_len = bytes[idx + 1] | (bytes[idx + 2] << 8)
            available = [data_len, n - (idx + 3)].min
            size = 3 + available
            ops << {
              offset: offset,
              opcode: op,
              name: 'OP_PUSHDATA2',
              size: size,
              push_encoding: :pushdata2,
              data_length: data_len
            }
            idx += size
            break if available < data_len
          elsif op == 0x4e
            # OP_PUSHDATA4: 4 byte LE length
            if idx + 4 >= n
              ops << {
                offset: offset,
                opcode: op,
                name: 'OP_PUSHDATA4',
                size: n - idx,
                push_encoding: :pushdata4,
                data_length: 0
              }
              break
            end
            data_len = bytes[idx + 1] | (bytes[idx + 2] << 8) |
                       (bytes[idx + 3] << 16) | (bytes[idx + 4] << 24)
            available = [data_len, n - (idx + 5)].min
            size = 5 + available
            ops << {
              offset: offset,
              opcode: op,
              name: 'OP_PUSHDATA4',
              size: size,
              push_encoding: :pushdata4,
              data_length: data_len
            }
            idx += size
            break if available < data_len
          else
            ops << {
              offset: offset,
              opcode: op,
              name: opcode_name(op),
              size: 1
            }
            idx += 1
          end
        end

        ops
      end
    end
  end
end
