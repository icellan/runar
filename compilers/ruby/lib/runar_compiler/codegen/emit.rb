# frozen_string_literal: true

# Stack IR to Bitcoin Script emission.
#
# Converts Stack IR (list of StackOp) to hex-encoded Bitcoin Script and
# human-readable ASM.
#
# Port of compilers/python/runar_compiler/codegen/emit.py

module RunarCompiler
  module Codegen
    # ------------------------------------------------------------------
    # Opcode table -- complete BSV opcode set
    # ------------------------------------------------------------------

    OPCODES = {
      "OP_0"                   => 0x00,
      "OP_FALSE"               => 0x00,
      "OP_PUSHDATA1"           => 0x4c,
      "OP_PUSHDATA2"           => 0x4d,
      "OP_PUSHDATA4"           => 0x4e,
      "OP_1NEGATE"             => 0x4f,
      "OP_1"                   => 0x51,
      "OP_TRUE"                => 0x51,
      "OP_2"                   => 0x52,
      "OP_3"                   => 0x53,
      "OP_4"                   => 0x54,
      "OP_5"                   => 0x55,
      "OP_6"                   => 0x56,
      "OP_7"                   => 0x57,
      "OP_8"                   => 0x58,
      "OP_9"                   => 0x59,
      "OP_10"                  => 0x5a,
      "OP_11"                  => 0x5b,
      "OP_12"                  => 0x5c,
      "OP_13"                  => 0x5d,
      "OP_14"                  => 0x5e,
      "OP_15"                  => 0x5f,
      "OP_16"                  => 0x60,
      "OP_NOP"                 => 0x61,
      "OP_IF"                  => 0x63,
      "OP_NOTIF"               => 0x64,
      "OP_ELSE"                => 0x67,
      "OP_ENDIF"               => 0x68,
      "OP_VERIFY"              => 0x69,
      "OP_RETURN"              => 0x6a,
      "OP_TOALTSTACK"          => 0x6b,
      "OP_FROMALTSTACK"        => 0x6c,
      "OP_2DROP"               => 0x6d,
      "OP_2DUP"                => 0x6e,
      "OP_3DUP"                => 0x6f,
      "OP_2OVER"               => 0x70,
      "OP_2ROT"                => 0x71,
      "OP_2SWAP"               => 0x72,
      "OP_IFDUP"               => 0x73,
      "OP_DEPTH"               => 0x74,
      "OP_DROP"                => 0x75,
      "OP_DUP"                 => 0x76,
      "OP_NIP"                 => 0x77,
      "OP_OVER"                => 0x78,
      "OP_PICK"                => 0x79,
      "OP_ROLL"                => 0x7a,
      "OP_ROT"                 => 0x7b,
      "OP_SWAP"                => 0x7c,
      "OP_TUCK"                => 0x7d,
      "OP_CAT"                 => 0x7e,
      "OP_SPLIT"               => 0x7f,
      "OP_NUM2BIN"             => 0x80,
      "OP_BIN2NUM"             => 0x81,
      "OP_SIZE"                => 0x82,
      "OP_INVERT"              => 0x83,
      "OP_AND"                 => 0x84,
      "OP_OR"                  => 0x85,
      "OP_XOR"                 => 0x86,
      "OP_EQUAL"               => 0x87,
      "OP_EQUALVERIFY"         => 0x88,
      "OP_1ADD"                => 0x8b,
      "OP_1SUB"                => 0x8c,
      "OP_2MUL"                => 0x8d, # Chronicle: multiply by 2
      "OP_2DIV"                => 0x8e, # Chronicle: divide by 2
      "OP_NEGATE"              => 0x8f,
      "OP_ABS"                 => 0x90,
      "OP_NOT"                 => 0x91,
      "OP_0NOTEQUAL"           => 0x92,
      "OP_ADD"                 => 0x93,
      "OP_SUB"                 => 0x94,
      "OP_MUL"                 => 0x95,
      "OP_DIV"                 => 0x96,
      "OP_MOD"                 => 0x97,
      "OP_LSHIFT"              => 0x98,
      "OP_RSHIFT"              => 0x99,
      "OP_BOOLAND"             => 0x9a,
      "OP_BOOLOR"              => 0x9b,
      "OP_NUMEQUAL"            => 0x9c,
      "OP_NUMEQUALVERIFY"      => 0x9d,
      "OP_NUMNOTEQUAL"         => 0x9e,
      "OP_LESSTHAN"            => 0x9f,
      "OP_GREATERTHAN"         => 0xa0,
      "OP_LESSTHANOREQUAL"     => 0xa1,
      "OP_GREATERTHANOREQUAL"  => 0xa2,
      "OP_MIN"                 => 0xa3,
      "OP_MAX"                 => 0xa4,
      "OP_WITHIN"              => 0xa5,
      "OP_RIPEMD160"           => 0xa6,
      "OP_SHA1"                => 0xa7,
      "OP_SHA256"              => 0xa8,
      "OP_HASH160"             => 0xa9,
      "OP_HASH256"             => 0xaa,
      "OP_CODESEPARATOR"       => 0xab,
      "OP_CHECKSIG"            => 0xac,
      "OP_CHECKSIGVERIFY"      => 0xad,
      "OP_CHECKMULTISIG"       => 0xae,
      "OP_CHECKMULTISIGVERIFY" => 0xaf,
      "OP_SUBSTR"              => 0xb3, # Chronicle: substring
      "OP_LEFT"                => 0xb4, # Chronicle: left N chars
      "OP_RIGHT"               => 0xb5, # Chronicle: right N chars
      "OP_LSHIFTNUM"           => 0xb6, # Chronicle: numeric left-shift
      "OP_RSHIFTNUM"           => 0xb7, # Chronicle: numeric right-shift
    }.freeze

    # ------------------------------------------------------------------
    # ConstructorSlot
    # ------------------------------------------------------------------

    # Records the byte offset of a constructor parameter placeholder.
    ConstructorSlot = Struct.new(:param_index, :byte_offset, keyword_init: true) do
      def initialize(param_index: 0, byte_offset: 0)
        super
      end
    end

    # ------------------------------------------------------------------
    # SourceMapping
    # ------------------------------------------------------------------

    # Maps an emitted opcode to a source location.
    SourceMapping = Struct.new(:opcode_index, :source_file, :line, :column, keyword_init: true) do
      def initialize(opcode_index: 0, source_file: "", line: 0, column: 0)
        super
      end
    end

    # ------------------------------------------------------------------
    # EmitResult
    # ------------------------------------------------------------------

    # Records the byte offset of a codeSepIndex placeholder (OP_0) in the
    # emitted script.  The SDK replaces it with the adjusted
    # codeSeparatorIndex at deployment time.
    CodeSepIndexSlot = Struct.new(:byte_offset, :code_sep_index, keyword_init: true) do
      def initialize(byte_offset: 0, code_sep_index: 0)
        super
      end
    end

    # Holds the outputs of the emission pass.
    EmitResult = Struct.new(
      :script_hex,
      :script_asm,
      :source_map,
      :constructor_slots,
      :code_sep_index_slots,
      :code_separator_index,
      :code_separator_indices,
      keyword_init: true
    ) do
      def initialize(
        script_hex: "",
        script_asm: "",
        source_map: [],
        constructor_slots: [],
        code_sep_index_slots: [],
        code_separator_index: -1,
        code_separator_indices: []
      )
        super
      end
    end

    # ------------------------------------------------------------------
    # Script number encoding
    # ------------------------------------------------------------------

    # Encode an integer as a Bitcoin Script number.
    #
    # Little-endian, sign-magnitude with sign bit in MSB.
    #
    # @param n [Integer]
    # @return [String] raw binary string of encoded bytes
    def self.encode_script_number(n)
      return "".b if n == 0

      negative = n < 0
      abs_n = n.abs

      result = []
      while abs_n > 0
        result << (abs_n & 0xFF)
        abs_n >>= 8
      end

      last_byte = result[-1]
      if (last_byte & 0x80) != 0
        if negative
          result << 0x80
        else
          result << 0x00
        end
      elsif negative
        result[-1] = last_byte | 0x80
      end

      result.pack("C*")
    end

    # ------------------------------------------------------------------
    # Push data encoding
    # ------------------------------------------------------------------

    # Encode raw bytes as a Bitcoin Script push-data operation.
    #
    # @param data [String] binary string of data bytes
    # @return [String] binary string of the encoded push-data operation
    def self.encode_push_data(data)
      length = data.bytesize

      if length == 0
        return [0x00].pack("C") # OP_0
      end

      # MINIMALDATA: single-byte values 1-16 must use OP_1..OP_16,
      # 0x81 must use OP_1NEGATE.
      # Note: 0x00 is NOT converted to OP_0 because OP_0 pushes empty []
      # not [0x00].
      if length == 1
        b = data.getbyte(0)
        if b >= 1 && b <= 16
          return [0x50 + b].pack("C") # OP_1 through OP_16
        end
        if b == 0x81
          return [0x4F].pack("C") # OP_1NEGATE
        end
      end

      if length >= 1 && length <= 75
        return [length].pack("C") + data
      end

      if length >= 76 && length <= 255
        return [0x4C, length].pack("CC") + data # OP_PUSHDATA1
      end

      if length >= 256 && length <= 65535
        return [0x4D, length & 0xFF, (length >> 8) & 0xFF].pack("CCC") + data # OP_PUSHDATA2
      end

      # OP_PUSHDATA4
      [
        0x4E,
        length & 0xFF,
        (length >> 8) & 0xFF,
        (length >> 16) & 0xFF,
        (length >> 24) & 0xFF,
      ].pack("CCCCC") + data
    end

    # ------------------------------------------------------------------
    # Push value encoding
    # ------------------------------------------------------------------

    # Convert a PushValue hash to [hex_str, asm_str].
    #
    # A PushValue is a hash with:
    #   :kind     - "bigint", "bool", or "bytes"
    #   :big_int  - Integer (for kind "bigint")
    #   :bool_val - true/false (for kind "bool")
    #   :bytes_val - binary String (for kind "bytes")
    #
    # @param value [Hash] push value descriptor
    # @return [Array(String, String)] hex string and ASM string
    def self.encode_push_value(value)
      kind = value[:kind]

      if kind == "bool"
        if value[:bool_val]
          return ["51", "OP_TRUE"]
        end
        return ["00", "OP_FALSE"]
      end

      if kind == "bigint"
        n = value[:big_int] || 0
        return encode_push_big_int(n)
      end

      if kind == "bytes"
        data = value[:bytes_val] || "".b
        encoded = encode_push_data(data)
        h = bytes_to_hex(encoded)
        if data.bytesize == 0
          return [h, "OP_0"]
        end
        return [h, "<#{bytes_to_hex(data)}>"]
      end

      # default
      ["00", "OP_0"]
    end

    # Encode an integer as a push operation, using small-integer opcodes
    # where possible.
    #
    # @param n [Integer]
    # @return [Array(String, String)] hex string and ASM string
    def self.encode_push_big_int(n)
      if n == 0
        return ["00", "OP_0"]
      end

      if n == -1
        return ["4f", "OP_1NEGATE"]
      end

      if n > 0 && n <= 16
        opcode = 0x50 + n
        return [format("%02x", opcode), "OP_#{n}"]
      end

      num_bytes = encode_script_number(n)
      encoded = encode_push_data(num_bytes)
      [bytes_to_hex(encoded), "<#{bytes_to_hex(num_bytes)}>"]
    end

    # ------------------------------------------------------------------
    # Hex utility
    # ------------------------------------------------------------------

    # Convert a binary string to lowercase hex.
    #
    # @param bytes_str [String] binary string
    # @return [String] hex-encoded string
    def self.bytes_to_hex(bytes_str)
      bytes_str.unpack1("H*")
    end

    # Convert a hex string to a binary string.
    #
    # @param hex_str [String] hex-encoded string
    # @return [String] binary string
    def self.hex_to_bytes(hex_str)
      [hex_str].pack("H*")
    end

    # ------------------------------------------------------------------
    # Emit context (internal)
    # ------------------------------------------------------------------

    # @api private
    class EmitContext
      attr_reader :source_map, :constructor_slots, :code_sep_index_slots,
                  :code_separator_index, :code_separator_indices

      def initialize
        @hex_parts = []
        @asm_parts = []
        @byte_length = 0
        @opcode_index = 0
        @source_map = []
        @pending_source_loc = nil
        @constructor_slots = []
        @code_sep_index_slots = []
        @code_separator_index = -1
        @code_separator_indices = []
      end

      def set_source_loc(loc)
        @pending_source_loc = loc
      end

      def emit_opcode(name)
        b = OPCODES[name]
        raise ArgumentError, "unknown opcode: #{name}" if b.nil?

        if name == "OP_CODESEPARATOR"
          @code_separator_index = @byte_length
          @code_separator_indices << @byte_length
        end

        record_source_mapping
        advance_opcode_index
        append_hex(format("%02x", b))
        append_asm(name)
      end

      def emit_push(value)
        h, a = Codegen.encode_push_value(value)
        record_source_mapping
        advance_opcode_index
        append_hex(h)
        append_asm(a)
      end

      def emit_placeholder(param_index)
        byte_offset = @byte_length
        record_source_mapping
        advance_opcode_index
        append_hex("00") # OP_0 placeholder byte
        append_asm("OP_0")
        @constructor_slots << ConstructorSlot.new(
          param_index: param_index,
          byte_offset: byte_offset
        )
      end

      def emit_code_sep_index_placeholder(code_sep_idx)
        byte_offset = @byte_length
        record_source_mapping
        advance_opcode_index
        append_hex("00") # OP_0 placeholder byte
        append_asm("OP_0")
        @code_sep_index_slots << CodeSepIndexSlot.new(
          byte_offset: byte_offset,
          code_sep_index: code_sep_idx
        )
      end

      def get_hex
        @hex_parts.join
      end

      def get_asm
        @asm_parts.join(" ")
      end

      private

      def record_source_mapping
        return unless @pending_source_loc

        @source_map << SourceMapping.new(
          opcode_index: @opcode_index,
          source_file: @pending_source_loc[:file] || "",
          line: @pending_source_loc[:line] || 0,
          column: @pending_source_loc[:column] || 0
        )
      end

      def advance_opcode_index
        idx = @opcode_index
        @opcode_index += 1
        idx
      end

      def append_hex(h)
        @hex_parts << h
        @byte_length += h.length / 2
      end

      def append_asm(a)
        @asm_parts << a
      end
    end

    # ------------------------------------------------------------------
    # Emit a single StackOp (internal)
    # ------------------------------------------------------------------

    # @api private
    def self.emit_stack_op(op, ctx)
      # Propagate source location from StackOp to the emit context
      ctx.set_source_loc(op[:source_loc]) if op[:source_loc]

      case op[:op]
      when "push"
        ctx.emit_push(op[:value])
      when "dup"
        ctx.emit_opcode("OP_DUP")
      when "swap"
        ctx.emit_opcode("OP_SWAP")
      when "roll"
        ctx.emit_opcode("OP_ROLL")
      when "pick"
        ctx.emit_opcode("OP_PICK")
      when "drop"
        ctx.emit_opcode("OP_DROP")
      when "nip"
        ctx.emit_opcode("OP_NIP")
      when "over"
        ctx.emit_opcode("OP_OVER")
      when "rot"
        ctx.emit_opcode("OP_ROT")
      when "tuck"
        ctx.emit_opcode("OP_TUCK")
      when "opcode"
        ctx.emit_opcode(op[:code])
      when "if"
        emit_if(op[:then] || [], op[:else_ops] || [], ctx)
      when "placeholder"
        ctx.emit_placeholder(op[:param_index] || 0)
      when "push_codesep_index"
        # Emit an OP_0 placeholder that the SDK will replace with the
        # adjusted codeSeparatorIndex at runtime.
        code_sep_idx = ctx.code_separator_index >= 0 ? ctx.code_separator_index : 0
        ctx.emit_code_sep_index_placeholder(code_sep_idx)
      else
        raise ArgumentError, "unknown stack op: #{op[:op]}"
      end

      # Clear after emitting so the location doesn't leak to the next op
      ctx.set_source_loc(nil)
    end

    # @api private
    def self.emit_if(then_ops, else_ops, ctx)
      ctx.emit_opcode("OP_IF")

      then_ops.each { |op| emit_stack_op(op, ctx) }

      unless else_ops.empty?
        ctx.emit_opcode("OP_ELSE")
        else_ops.each { |op| emit_stack_op(op, ctx) }
      end

      ctx.emit_opcode("OP_ENDIF")
    end

    # ------------------------------------------------------------------
    # Method dispatch
    # ------------------------------------------------------------------

    # Emit a method selector preamble for multi-method contracts.
    #
    # @api private
    def self.emit_method_dispatch(methods, ctx)
      methods.each_with_index do |method, i|
        is_last = i == methods.length - 1

        if !is_last
          ctx.emit_opcode("OP_DUP")
          ctx.emit_push({ kind: "bigint", big_int: i })
          ctx.emit_opcode("OP_NUMEQUAL")
          ctx.emit_opcode("OP_IF")
          ctx.emit_opcode("OP_DROP")
        else
          # Last method -- verify the index matches (fail-closed for invalid selectors)
          ctx.emit_push({ kind: "bigint", big_int: i })
          ctx.emit_opcode("OP_NUMEQUALVERIFY")
        end

        method[:ops].each { |op| emit_stack_op(op, ctx) }

        if !is_last
          ctx.emit_opcode("OP_ELSE")
        end
      end

      # Close all nested OP_IF/OP_ELSE blocks
      (methods.length - 1).times do
        ctx.emit_opcode("OP_ENDIF")
      end
    end

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    # Convert a list of StackMethods into Bitcoin Script hex and ASM.
    #
    # For contracts with multiple public methods, generates a method dispatch
    # preamble using OP_IF/OP_ELSE chains.
    #
    # Note: peephole optimization (VERIFY combinations, SWAP elimination) is
    # handled by optimize_stack_ops in optimizer.rb, which runs before emit.
    #
    # @param methods [Array<Hash>] list of stack method hashes, each with
    #   :name [String] and :ops [Array<Hash>]
    # @return [EmitResult]
    def self.emit(methods)
      ctx = EmitContext.new

      # Filter to public methods (exclude constructor)
      public_methods = methods.reject { |m| m[:name] == "constructor" }

      if public_methods.empty?
        return EmitResult.new(
          script_hex: "",
          script_asm: "",
          source_map: [],
          constructor_slots: [],
          code_sep_index_slots: []
        )
      end

      if public_methods.length == 1
        # Single public method -- no dispatch needed
        public_methods[0][:ops].each { |op| emit_stack_op(op, ctx) }
      else
        # Multiple public methods -- emit dispatch table
        emit_method_dispatch(public_methods, ctx)
      end

      EmitResult.new(
        script_hex: ctx.get_hex,
        script_asm: ctx.get_asm,
        source_map: ctx.source_map,
        constructor_slots: ctx.constructor_slots,
        code_sep_index_slots: ctx.code_sep_index_slots,
        code_separator_index: ctx.code_separator_index,
        code_separator_indices: ctx.code_separator_indices
      )
    end

    # Emit a single method's ops. Useful for testing.
    #
    # @param method [Hash] stack method hash with :name and :ops
    # @return [EmitResult]
    def self.emit_method(method)
      ctx = EmitContext.new

      method[:ops].each { |op| emit_stack_op(op, ctx) }

      EmitResult.new(
        script_hex: ctx.get_hex,
        script_asm: ctx.get_asm,
        source_map: ctx.source_map,
        constructor_slots: ctx.constructor_slots,
        code_sep_index_slots: ctx.code_sep_index_slots,
        code_separator_index: ctx.code_separator_index,
        code_separator_indices: ctx.code_separator_indices
      )
    end
  end
end
