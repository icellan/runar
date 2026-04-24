# frozen_string_literal: true

# Stack IR lowering -- converts ANF IR to Stack IR (Bitcoin Script stack ops).
#
# This is the core code-generation pass of the Runar compiler.  It takes the
# A-Normal Form intermediate representation and produces a sequence of abstract
# stack-machine operations that map 1-to-1 to Bitcoin Script opcodes.
#
# Port of compilers/python/runar_compiler/codegen/stack.py

require_relative "../ir/types"

module RunarCompiler::Codegen
  # -----------------------------------------------------------------------
  # Constants
  # -----------------------------------------------------------------------

  MAX_STACK_DEPTH = 800

  # Builtin function -> opcode mapping
  BUILTIN_OPCODES = {
    "sha256"        => ["OP_SHA256"],
    "ripemd160"     => ["OP_RIPEMD160"],
    "hash160"       => ["OP_HASH160"],
    "hash256"       => ["OP_HASH256"],
    "checkSig"      => ["OP_CHECKSIG"],
    "checkMultiSig" => ["OP_CHECKMULTISIG"],
    "len"           => ["OP_SIZE"],
    "cat"           => ["OP_CAT"],
    "num2bin"       => ["OP_NUM2BIN"],
    "bin2num"       => ["OP_BIN2NUM"],
    "abs"           => ["OP_ABS"],
    "min"           => ["OP_MIN"],
    "max"           => ["OP_MAX"],
    "within"        => ["OP_WITHIN"],
    "split"         => ["OP_SPLIT"],
    "left"          => ["OP_SPLIT", "OP_DROP"],
    "int2str"       => ["OP_NUM2BIN"],
    "bool"          => ["OP_0NOTEQUAL"],
    "unpack"        => ["OP_BIN2NUM"],
  }.freeze

  # Binary operator -> opcode mapping
  BINOP_OPCODES = {
    "+"   => ["OP_ADD"],
    "-"   => ["OP_SUB"],
    "*"   => ["OP_MUL"],
    "/"   => ["OP_DIV"],
    "%"   => ["OP_MOD"],
    "===" => ["OP_NUMEQUAL"],
    "!==" => ["OP_NUMEQUAL", "OP_NOT"],
    "<"   => ["OP_LESSTHAN"],
    ">"   => ["OP_GREATERTHAN"],
    "<="  => ["OP_LESSTHANOREQUAL"],
    ">="  => ["OP_GREATERTHANOREQUAL"],
    "&&"  => ["OP_BOOLAND"],
    "||"  => ["OP_BOOLOR"],
    "&"   => ["OP_AND"],
    "|"   => ["OP_OR"],
    "^"   => ["OP_XOR"],
    "<<"  => ["OP_LSHIFT"],
    ">>"  => ["OP_RSHIFT"],
  }.freeze

  # Unary operator -> opcode mapping
  UNARYOP_OPCODES = {
    "!" => ["OP_NOT"],
    "-" => ["OP_NEGATE"],
    "~" => ["OP_INVERT"],
  }.freeze

  # EC builtin function names
  EC_BUILTIN_NAMES = Set.new(%w[
    ecAdd ecMul ecMulGen
    ecNegate ecOnCurve ecModReduce
    ecEncodeCompressed ecMakePoint
    ecPointX ecPointY
  ]).freeze

  # NIST EC (P-256 / P-384) builtin function names
  NIST_EC_BUILTIN_NAMES = Set.new(%w[
    p256Add p256Mul p256MulGen p256Negate p256OnCurve p256EncodeCompressed
    p384Add p384Mul p384MulGen p384Negate p384OnCurve p384EncodeCompressed
  ]).freeze

  # ECDSA verification function names
  VERIFY_ECDSA_NAMES = Set.new(%w[verifyECDSA_P256 verifyECDSA_P384]).freeze

  # Baby Bear field arithmetic builtin function names
  BB_BUILTIN_NAMES = Set.new(%w[
    bbFieldAdd bbFieldSub bbFieldMul bbFieldInv
    bbExt4Mul0 bbExt4Mul1 bbExt4Mul2 bbExt4Mul3
    bbExt4Inv0 bbExt4Inv1 bbExt4Inv2 bbExt4Inv3
  ]).freeze

  # KoalaBear field arithmetic builtin function names
  KB_BUILTIN_NAMES = Set.new(%w[
    kbFieldAdd kbFieldSub kbFieldMul kbFieldInv
    kbExt4Mul0 kbExt4Mul1 kbExt4Mul2 kbExt4Mul3
    kbExt4Inv0 kbExt4Inv1 kbExt4Inv2 kbExt4Inv3
  ]).freeze

  # BN254 field arithmetic and G1 curve builtin function names
  BN254_BUILTIN_NAMES = Set.new(%w[
    bn254FieldAdd bn254FieldSub bn254FieldMul bn254FieldInv bn254FieldNeg
    bn254G1Add bn254G1ScalarMul bn254G1Negate bn254G1OnCurve
  ]).freeze

  # Merkle proof verification builtin function names
  MERKLE_BUILTIN_NAMES = Set.new(%w[
    merkleRootSha256 merkleRootHash256
  ]).freeze

  # -----------------------------------------------------------------------
  # StackMap -- tracks named values on the stack
  # -----------------------------------------------------------------------

  class StackMap
    attr_reader :slots

    # @param initial [Array<String>, nil] initial slot names
    def initialize(initial = nil)
      @slots = initial ? initial.dup : []
    end

    def depth
      @slots.length
    end

    # @param name [String] name to push
    def push(name)
      @slots.push(name)
    end

    # @return [String] popped name
    def pop
      raise "stack underflow" if @slots.empty?

      @slots.pop
    end

    # Return distance from top of stack to +name+.  0 = TOS.  -1 if absent.
    #
    # @param name [String]
    # @return [Integer]
    def find_depth(name)
      i = @slots.length - 1
      while i >= 0
        return @slots.length - 1 - i if @slots[i] == name

        i -= 1
      end
      -1
    end

    # @param name [String]
    # @return [Boolean]
    def has?(name)
      @slots.include?(name)
    end

    # Remove the entry at the given depth from top.
    #
    # @param depth_from_top [Integer]
    # @return [String] removed name
    def remove_at_depth(depth_from_top)
      index = @slots.length - 1 - depth_from_top
      raise "invalid stack depth: #{depth_from_top}" if index < 0 || index >= @slots.length

      @slots.delete_at(index)
    end

    # Peek at the entry at the given depth from top.
    #
    # @param depth_from_top [Integer]
    # @return [String]
    def peek_at_depth(depth_from_top)
      index = @slots.length - 1 - depth_from_top
      raise "invalid stack depth: #{depth_from_top}" if index < 0 || index >= @slots.length

      @slots[index]
    end

    # @return [StackMap] deep copy
    def clone
      sm = StackMap.new
      sm.instance_variable_set(:@slots, @slots.dup)
      sm
    end

    def swap
      n = @slots.length
      raise "stack underflow on swap" if n < 2

      @slots[n - 1], @slots[n - 2] = @slots[n - 2], @slots[n - 1]
    end

    def dup
      raise "stack underflow on dup" if @slots.empty?

      @slots.push(@slots.last)
    end

    # Rename a slot at a given depth from top.
    #
    # @param depth_from_top [Integer]
    # @param new_name [String, nil]
    def rename_at_depth(depth_from_top, new_name)
      idx = @slots.length - 1 - depth_from_top
      raise "invalid stack depth for rename: #{depth_from_top}" if idx < 0 || idx >= @slots.length

      @slots[idx] = new_name || ""
    end

    # @return [Set<String>] set of all non-empty slot names
    def named_slots
      result = Set.new
      @slots.each { |s| result.add(s) if s && !s.empty? }
      result
    end
  end

  # -----------------------------------------------------------------------
  # Use analysis -- determine last-use sites for each variable
  # -----------------------------------------------------------------------

  # @param bindings [Array<IR::ANFBinding>]
  # @return [Hash{String => Integer}]
  def self.compute_last_uses(bindings)
    last_use = {}
    bindings.each_with_index do |binding, i|
      refs = collect_refs(binding.value)
      refs.each { |ref| last_use[ref] = i }
    end
    last_use
  end

  # Collect all variable references from an ANF value.
  #
  # @param value [IR::ANFValue]
  # @return [Array<String>]
  def self.collect_refs(value)
    refs = []
    kind = value.kind

    case kind
    when "load_param"
      refs << value.name
    when "load_prop", "get_state_script"
      # no refs
    when "load_const"
      if value.const_string && value.const_string.length > 5 && value.const_string[0, 5] == "@ref:"
        refs << value.const_string[5..]
      end
    when "bin_op"
      refs << value.left
      refs << value.right
    when "unary_op"
      refs << value.operand
    when "call"
      refs.concat(value.args) if value.args
    when "method_call"
      refs << value.object
      refs.concat(value.args) if value.args
    when "if"
      refs << value.cond
      (value.then || []).each { |b| refs.concat(collect_refs(b.value)) }
      (value.else_ || []).each { |b| refs.concat(collect_refs(b.value)) }
    when "loop"
      (value.body || []).each { |b| refs.concat(collect_refs(b.value)) }
    when "assert"
      refs << value.value_ref
    when "update_prop"
      refs << value.value_ref
    when "check_preimage"
      refs << value.preimage
    when "deserialize_state"
      refs << value.preimage
    when "add_output"
      refs << value.satoshis
      refs.concat(value.state_values) if value.state_values
      refs << value.preimage if value.preimage
    when "add_raw_output"
      refs << value.satoshis
      refs << value.script_bytes
    when "add_data_output"
      refs << value.satoshis
      refs << value.script_bytes
    when "array_literal"
      refs.concat(value.elements) if value.elements
    end

    refs
  end

  # -----------------------------------------------------------------------
  # Helpers
  # -----------------------------------------------------------------------

  # @param n [Integer]
  # @return [Hash] PushValue hash for a big integer
  def self.big_int_push(n)
    { kind: "bigint", big_int: n }
  end

  # @param h [String] hex string
  # @return [String] binary string
  def self.hex_to_bytes(h)
    [h].pack("H*")
  end

  # -----------------------------------------------------------------------
  # EC builtin check
  # -----------------------------------------------------------------------

  # @param name [String]
  # @return [Boolean]
  def self.ec_builtin?(name)
    EC_BUILTIN_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.nist_ec_builtin?(name)
    NIST_EC_BUILTIN_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.verify_ecdsa_builtin?(name)
    VERIFY_ECDSA_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.bb_builtin?(name)
    BB_BUILTIN_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.kb_builtin?(name)
    KB_BUILTIN_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.bn254_builtin?(name)
    BN254_BUILTIN_NAMES.include?(name)
  end

  # @param name [String]
  # @return [Boolean]
  def self.merkle_builtin?(name)
    MERKLE_BUILTIN_NAMES.include?(name)
  end

  # -----------------------------------------------------------------------
  # Method analysis helpers
  # -----------------------------------------------------------------------

  # @param bindings [Array<IR::ANFBinding>]
  # @return [Boolean]
  def self.method_uses_check_preimage?(bindings)
    bindings.any? { |b| b.value.kind == "check_preimage" }
  end

  # Check whether a method has add_output, add_raw_output, add_data_output,
  # or computeStateOutput/computeStateOutputHash calls (recursively).
  #
  # @param bindings [Array<IR::ANFBinding>]
  # @return [Boolean]
  def self.method_uses_code_part?(bindings)
    bindings.each do |b|
      return true if %w[add_output add_raw_output add_data_output].include?(b.value.kind)
      if b.value.kind == "call" && %w[computeStateOutput computeStateOutputHash].include?(b.value.func)
        return true
      end
      if b.value.kind == "if"
        then_bindings = b.value.then || []
        else_bindings = b.value.else_ || []
        return true if method_uses_code_part?(then_bindings) || method_uses_code_part?(else_bindings)
      end
      if b.value.kind == "loop"
        body_bindings = b.value.body || []
        return true if method_uses_code_part?(body_bindings)
      end
    end
    false
  end

  # -----------------------------------------------------------------------
  # State-property type classification helpers
  # -----------------------------------------------------------------------

  # State-field types that are stored as script numbers (require OP_BIN2NUM
  # after extraction). `RabinSig`/`RabinPubKey` are bigint aliases.
  NUMERIC_STATE_TYPES = %w[bigint boolean RabinSig RabinPubKey].to_set.freeze

  # State-field types that are stored with a push-data length prefix and thus
  # require `emit_push_data_decode` instead of a fixed OP_SPLIT.
  VARIABLE_LENGTH_STATE_TYPES = %w[ByteString Sig SigHashPreimage].to_set.freeze

  # @param t [String]
  # @return [Boolean]
  def self.numeric_state_type?(t)
    NUMERIC_STATE_TYPES.include?(t)
  end

  # @param t [String]
  # @return [Boolean]
  def self.variable_length_state_type?(t)
    VARIABLE_LENGTH_STATE_TYPES.include?(t)
  end

  # -----------------------------------------------------------------------
  # LoweringContext -- mutable state for the stack-lowering pass
  # -----------------------------------------------------------------------

  class LoweringContext
    attr_accessor :sm, :ops, :max_depth, :properties, :private_methods,
                  :local_bindings, :outer_protected_refs, :inside_branch,
                  :current_source_loc

    # @param params [Array<String>, nil] initial stack parameter names
    # @param properties [Array<IR::ANFProperty>]
    def initialize(params, properties)
      @sm = StackMap.new(params || [])
      @ops = []
      @max_depth = 0
      @properties = properties
      @private_methods = {}
      @local_bindings = {}
      @array_lengths = {}
      @const_values = {}
      @outer_protected_refs = nil
      @inside_branch = false
      @current_source_loc = nil
      _track_depth
    end

    # -----------------------------------------------------------------
    # Emit helpers
    # -----------------------------------------------------------------

    # Emit a StackOp hash to the ops list.
    #
    # @param op [Hash] StackOp hash
    def emit_op(op)
      if @current_source_loc && op[:source_loc].nil?
        op[:source_loc] = @current_source_loc
      end
      @ops << op
      _track_depth
    end

    # Emit a push operation with a bigint value.
    #
    # @param n [Integer]
    def emit_push_int(n)
      emit_op({ op: "push", value: RunarCompiler::Codegen.big_int_push(n) })
    end

    # Emit a push operation with a bytes value.
    #
    # @param bytes_val [String] binary string
    def emit_push_bytes(bytes_val)
      emit_op({ op: "push", value: { kind: "bytes", bytes_val: bytes_val } })
    end

    # Emit a push operation with a bool value.
    #
    # @param val [Boolean]
    def emit_push_bool(val)
      emit_op({ op: "push", value: { kind: "bool", bool_val: val } })
    end

    # Emit an opcode.
    #
    # @param code [String] e.g. "OP_ADD"
    def emit_opcode(code)
      emit_op({ op: "opcode", code: code })
    end

    # Emit a dup operation.
    def emit_dup
      emit_op({ op: "dup" })
      @sm.dup
    end

    # Emit a drop operation.
    def emit_drop
      emit_op({ op: "drop" })
      @sm.pop
    end

    # Emit a swap operation.
    def emit_swap
      emit_op({ op: "swap" })
      @sm.swap
    end

    # Emit a nip (remove second-from-top).
    def emit_nip
      emit_op({ op: "nip" })
      @sm.remove_at_depth(1)
    end

    # Emit a roll with explicit depth push.
    #
    # @param depth [Integer]
    def emit_roll(depth)
      emit_push_int(depth)
      @sm.push("")
      emit_op({ op: "roll", depth: depth })
      @sm.pop # remove depth literal
      rolled = @sm.remove_at_depth(depth)
      @sm.push(rolled)
    end

    # Emit a pick with explicit depth push.
    #
    # @param depth [Integer]
    def emit_pick(depth)
      emit_push_int(depth)
      @sm.push("")
      emit_op({ op: "pick", depth: depth })
      @sm.pop # remove depth literal
      picked = @sm.peek_at_depth(depth)
      @sm.push(picked)
    end

    # -----------------------------------------------------------------
    # Varint encoding helper
    # -----------------------------------------------------------------

    # Emit Bitcoin varint encoding of the length on top of the stack.
    #
    # Expects stack: [..., script, len]
    # Leaves stack:  [..., script, varint_bytes]
    #
    # Bitcoin varint format:
    #   len < 0xfd:        1 byte (len itself)
    #   len <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
    #   len <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
    #   otherwise:         0xff + 8 bytes LE                (9 bytes — never
    #                                                        used in practice
    #                                                        for BSV scripts)
    #
    # We must support all four shapes; emitting a 3-byte varint for a script
    # whose length exceeds 0xffff produces a truncated value that no longer
    # matches what the BSV node uses for hashOutputs, breaking the
    # state-continuation hash equality assertion downstream.
    #
    # OP_NUM2BIN uses sign-magnitude encoding so high-bit values need an
    # extra sign byte; we generate one extra byte and then SPLIT off the
    # unsigned low bytes to get the correct unsigned varint payload.
    def emit_varint_encoding
      # Stack: [..., script, len]

      # emit_num_to_low_bytes: [..., len] -> [..., low_n_bytes]. Uses
      # NUM2BIN(n+1) then SPLIT(n) DROP to drop the sign byte.
      emit_num_to_low_bytes = lambda do |n_bytes|
        emit_push_int(n_bytes + 1)
        @sm.push("")
        emit_opcode("OP_NUM2BIN")
        @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(n_bytes)
        @sm.push("")
        emit_opcode("OP_SPLIT")
        @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" })
        @sm.pop
      end

      # emit_prefix: [..., script, low_bytes] -> [..., script, prefix||low_bytes].
      emit_prefix = lambda do |prefix_byte|
        emit_push_bytes([prefix_byte].pack("C"))
        @sm.push("")
        emit_op({ op: "swap" })
        @sm.swap
        @sm.pop; @sm.pop
        emit_opcode("OP_CAT")
        @sm.push("")
      end

      # IF len < 253: 1-byte varint.
      emit_op({ op: "dup" })
      @sm.dup
      emit_push_int(253)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_IF")
      @sm.pop
      sm_at_1byte = @sm.clone
      emit_num_to_low_bytes.call(1)
      emit_opcode("OP_ELSE")
      @sm = sm_at_1byte.clone

      # ELSE-IF len <= 0xffff: 0xfd + 2-byte LE.
      emit_op({ op: "dup" })
      @sm.dup
      emit_push_int(0x10000)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_IF")
      @sm.pop
      sm_at_3byte = @sm.clone
      emit_num_to_low_bytes.call(2)
      emit_prefix.call(0xfd)
      emit_opcode("OP_ELSE")
      @sm = sm_at_3byte.clone

      # ELSE-IF len <= 0xffffffff: 0xfe + 4-byte LE.
      emit_op({ op: "dup" })
      @sm.dup
      emit_push_int(0x100000000)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_IF")
      @sm.pop
      sm_at_5byte = @sm.clone
      emit_num_to_low_bytes.call(4)
      emit_prefix.call(0xfe)
      emit_opcode("OP_ELSE")
      @sm = sm_at_5byte.clone

      # ELSE: 0xff + 8-byte LE. (>= 4 GiB script — practically unreachable on
      # BSV but kept for spec completeness so we never silently truncate.)
      emit_num_to_low_bytes.call(8)
      emit_prefix.call(0xff)

      emit_opcode("OP_ENDIF")
      emit_opcode("OP_ENDIF")
      emit_opcode("OP_ENDIF")
      # --- Stack: [..., script, varint] ---
    end

    # -----------------------------------------------------------------
    # Push-data encode/decode helpers
    # -----------------------------------------------------------------

    # Emit push-data encoding for a ByteString value on top of the stack.
    #
    # Expects stack: [..., bs_value]
    # Leaves stack:  [..., pushdata_encoded_value]
    def emit_push_data_encode
      emit_opcode("OP_SIZE")
      @sm.push("")
      emit_op({ op: "dup" })
      @sm.push(@sm.peek_at_depth(0))
      emit_push_int(76)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")

      emit_opcode("OP_IF")
      @sm.pop
      sm_after_outer_if = @sm.clone

      # THEN: len <= 75
      emit_push_int(2)
      @sm.push("")
      emit_opcode("OP_NUM2BIN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_push_int(1)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT")
      @sm.push("")
      sm_end_target = @sm.clone

      emit_opcode("OP_ELSE")
      @sm = sm_after_outer_if.clone

      emit_op({ op: "dup" })
      @sm.push(@sm.peek_at_depth(0))
      emit_push_int(256)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")

      emit_opcode("OP_IF")
      @sm.pop
      sm_after_inner_if = @sm.clone

      # THEN: 76-255 -> 0x4c + 1-byte
      emit_push_int(2)
      @sm.push("")
      emit_opcode("OP_NUM2BIN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_push_int(1)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop
      emit_push_bytes([0x4C].pack("C"))
      @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT")
      @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT")
      @sm.push("")

      emit_opcode("OP_ELSE")
      @sm = sm_after_inner_if

      # ELSE: >= 256 -> 0x4d + 2-byte LE
      emit_push_int(4)
      @sm.push("")
      emit_opcode("OP_NUM2BIN")
      @sm.pop; @sm.pop; @sm.push("")
      emit_push_int(2)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop
      emit_push_bytes([0x4D].pack("C"))
      @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT")
      @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT")
      @sm.push("")

      emit_opcode("OP_ENDIF")
      emit_opcode("OP_ENDIF")
      @sm = sm_end_target
    end

    # Emit push-data decoding for a ByteString state field.
    #
    # Expects stack: [..., state_bytes]
    # Leaves stack:  [..., data, remaining_state]
    def emit_push_data_decode
      emit_push_int(1)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_BIN2NUM")
      emit_op({ op: "dup" })
      @sm.push(@sm.peek_at_depth(0))
      emit_push_int(76)
      @sm.push("")
      emit_opcode("OP_LESSTHAN")
      @sm.pop; @sm.pop; @sm.push("")

      emit_opcode("OP_IF")
      @sm.pop
      sm_after_outer_if = @sm.clone

      # THEN: fb < 76 -> direct length
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      sm_end_target = @sm.clone

      emit_opcode("OP_ELSE")
      @sm = sm_after_outer_if.clone

      emit_op({ op: "dup" })
      @sm.push(@sm.peek_at_depth(0))
      emit_push_int(77)
      @sm.push("")
      emit_opcode("OP_NUMEQUAL")
      @sm.pop; @sm.pop; @sm.push("")

      emit_opcode("OP_IF")
      @sm.pop
      sm_after_inner_if = @sm.clone

      # THEN: fb == 77 -> 2-byte LE
      emit_op({ op: "drop" }); @sm.pop
      emit_push_int(2)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_BIN2NUM")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")

      emit_opcode("OP_ELSE")
      @sm = sm_after_inner_if

      # ELSE: fb == 76 -> 1-byte
      emit_op({ op: "drop" }); @sm.pop
      emit_push_int(1)
      @sm.push("")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_BIN2NUM")
      emit_opcode("OP_SPLIT")
      @sm.pop; @sm.pop; @sm.push(""); @sm.push("")

      emit_opcode("OP_ENDIF")
      emit_opcode("OP_ENDIF")
      @sm = sm_end_target
    end

    # -----------------------------------------------------------------
    # bring_to_top
    # -----------------------------------------------------------------

    # Move +name+ to TOS.  ROLL if +consume+, else PICK (copy).
    #
    # @param name [String]
    # @param consume [Boolean]
    def bring_to_top(name, consume)
      depth = @sm.find_depth(name)
      raise "value #{name.inspect} not found on stack" if depth < 0

      if depth == 0
        unless consume
          emit_op({ op: "dup" })
          @sm.dup
        end
        return
      end

      if depth == 1 && consume
        emit_op({ op: "swap" })
        @sm.swap
        return
      end

      if consume
        if depth == 2
          # ROT is ROLL 2
          emit_op({ op: "rot" })
          removed = @sm.remove_at_depth(2)
          @sm.push(removed)
        else
          emit_push_int(depth)
          @sm.push("") # temporary depth literal on stack map
          emit_op({ op: "roll", depth: depth })
          @sm.pop # remove depth literal
          rolled = @sm.remove_at_depth(depth)
          @sm.push(rolled)
        end
      else
        if depth == 1
          emit_op({ op: "over" })
          picked = @sm.peek_at_depth(1)
          @sm.push(picked)
        else
          emit_push_int(depth)
          @sm.push("") # temporary depth literal
          emit_op({ op: "pick", depth: depth })
          @sm.pop # remove depth literal
          picked = @sm.peek_at_depth(depth)
          @sm.push(picked)
        end
      end

      _track_depth
    end

    # -----------------------------------------------------------------
    # resolve_ref -- resolve a binding name to bring it to top of stack
    # -----------------------------------------------------------------

    # Resolve a reference: bring the named value to TOS, consuming it
    # if this is its last use.
    #
    # @param ref [String] variable name
    # @param binding_index [Integer] current binding index
    # @param last_uses [Hash{String => Integer}]
    def resolve_ref(ref, binding_index, last_uses)
      is_last = _is_last_use(ref, binding_index, last_uses)
      bring_to_top(ref, is_last)
    end

    # -----------------------------------------------------------------
    # lower_bindings
    # -----------------------------------------------------------------

    # Lower a list of ANF bindings to stack operations.
    #
    # @param bindings [Array<IR::ANFBinding>]
    # @param terminal_assert [Boolean]
    def lower_bindings(bindings, terminal_assert)
      @local_bindings = {}
      bindings.each { |b| @local_bindings[b.name] = true }
      last_uses = RunarCompiler::Codegen.compute_last_uses(bindings)

      # Protect parent-scope refs that are still needed after this scope
      if @outer_protected_refs
        @outer_protected_refs.each do |ref|
          last_uses[ref] = bindings.length
        end
      end

      # Find terminal binding index
      last_assert_idx = -1
      terminal_if_idx = -1
      if terminal_assert
        last_binding = bindings.last
        if last_binding && last_binding.value.kind == "if"
          terminal_if_idx = bindings.length - 1
        else
          (bindings.length - 1).downto(0) do |i|
            if bindings[i].value.kind == "assert"
              last_assert_idx = i
              break
            end
          end
        end
      end

      bindings.each_with_index do |binding, i|
        # Propagate source location from ANF binding to StackOps
        @current_source_loc = binding.source_loc
        if binding.value.kind == "assert" && i == last_assert_idx
          # Terminal assert: leave value on stack instead of OP_VERIFY
          _lower_assert(binding.value.value_ref, i, last_uses, true)
        elsif binding.value.kind == "if" && i == terminal_if_idx
          # Terminal if: propagate terminalAssert into both branches
          _lower_if(
            binding.name, binding.value.cond,
            binding.value.then, binding.value.else_,
            i, last_uses, true
          )
        else
          lower_binding(binding, i, last_uses)
        end
        @current_source_loc = nil
      end
    end

    # Lower bindings but never consume protected names.
    #
    # @param bindings [Array<IR::ANFBinding>]
    # @param protected_names [Set<String>]
    def lower_bindings_protected(bindings, protected_names)
      last_uses = RunarCompiler::Codegen.compute_last_uses(bindings)

      # Ensure protected names are never consumed
      protected_names.each do |name|
        last_uses[name] = (1 << 31) - 1
      end

      bindings.each_with_index do |binding, i|
        @current_source_loc = binding.source_loc
        lower_binding(binding, i, last_uses)
        @current_source_loc = nil
      end
    end

    # -----------------------------------------------------------------
    # lower_binding -- dispatch on ANF value kind
    # -----------------------------------------------------------------

    # Lower a single ANF binding to stack operations.
    #
    # @param binding [IR::ANFBinding]
    # @param binding_index [Integer]
    # @param last_uses [Hash{String => Integer}]
    def lower_binding(binding, binding_index, last_uses)
      name = binding.name
      value = binding.value
      kind = value.kind

      case kind
      when "load_param"
        _lower_load_param(name, value.name, binding_index, last_uses)
      when "load_prop"
        _lower_load_prop(name, value.name)
      when "load_const"
        _lower_load_const(name, value, binding_index, last_uses)
      when "bin_op"
        _lower_bin_op(name, value.op, value.left, value.right, binding_index, last_uses, value.result_type)
      when "unary_op"
        _lower_unary_op(name, value.op, value.operand, binding_index, last_uses)
      when "call"
        _lower_call(name, value.func, value.args || [], binding_index, last_uses)
      when "method_call"
        _lower_method_call(name, value.object, value.method, value.args || [], binding_index, last_uses)
      when "assert"
        _lower_assert(value.value_ref, binding_index, last_uses, false)
      when "update_prop"
        _lower_update_prop(value.name, value.value_ref, binding_index, last_uses)

      # --- Advanced kinds ---
      when "if"
        _lower_if(name, value.cond, value.then, value.else_, binding_index, last_uses)
      when "loop"
        _lower_loop(name, value.count, value.body, value.iter_var)
      when "check_preimage"
        _lower_check_preimage(name, value.preimage, binding_index, last_uses)
      when "deserialize_state"
        _lower_deserialize_state(value.preimage, binding_index, last_uses)
      when "add_output"
        _lower_add_output(name, value.satoshis, value.state_values || [], value.preimage, binding_index, last_uses)
      when "add_raw_output"
        _lower_add_raw_output(name, value.satoshis, value.script_bytes, binding_index, last_uses)
      when "add_data_output"
        # Wire shape is identical to add_raw_output; the distinction only
        # matters at the continuation-hash composition stage in ANF.
        _lower_add_raw_output(name, value.satoshis, value.script_bytes, binding_index, last_uses)
      when "get_state_script"
        _lower_get_state_script(name)
      when "array_literal"
        _lower_array_literal(name, value.elements || [], binding_index, last_uses)
      end
    end

    private

    # -----------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------

    def _track_depth
      @max_depth = @sm.depth if @sm.depth > @max_depth
    end

    def _is_last_use(ref, current_index, last_uses)
      last = last_uses[ref]
      return true if last.nil?

      last <= current_index
    end

    # -----------------------------------------------------------------
    # load_param
    # -----------------------------------------------------------------

    def _lower_load_param(binding_name, param_name, binding_index, last_uses)
      if @sm.has?(param_name)
        is_last = _is_last_use(param_name, binding_index, last_uses)
        bring_to_top(param_name, is_last)
        @sm.pop
        @sm.push(binding_name)
      else
        emit_push_int(0)
        @sm.push(binding_name)
      end
    end

    # -----------------------------------------------------------------
    # load_prop
    # -----------------------------------------------------------------

    def _lower_load_prop(binding_name, prop_name)
      prop = @properties.find { |p| p.name == prop_name }

      if @sm.has?(prop_name)
        # Property has been updated -- use the stack value
        bring_to_top(prop_name, false)
        @sm.pop
      elsif prop && !prop.initial_value.nil?
        _push_property_value(prop.initial_value)
      else
        # Property value will be provided at deployment time; emit placeholder
        param_index = 0
        @properties.each do |p|
          next if p.initial_value
          if p.name == prop_name
            break
          end
          param_index += 1
        end
        emit_op({ op: "placeholder", param_index: param_index, param_name: prop_name })
      end
      @sm.push(binding_name)
    end

    def _push_property_value(val)
      case val
      when true, false
        emit_push_bool(val)
      when Integer
        emit_push_int(val)
      when Float
        emit_push_int(val.to_i)
      when String
        emit_push_bytes(RunarCompiler::Codegen.hex_to_bytes(val))
      else
        emit_push_int(0)
      end
    end

    # -----------------------------------------------------------------
    # load_const
    # -----------------------------------------------------------------

    def _lower_load_const(binding_name, value, binding_index, last_uses)
      # Handle @ref: aliases (ANF variable aliasing)
      if value.const_string && value.const_string.length > 5 && value.const_string[0, 5] == "@ref:"
        ref_name = value.const_string[5..]
        if @sm.has?(ref_name)
          # CRITICAL: Only consume (ROLL) if the ref target is a local binding
          # in the current scope.  Outer-scope refs must be copied (PICK) so
          # the parent stackMap stays in sync.
          consume = @local_bindings[ref_name] && _is_last_use(ref_name, binding_index, last_uses)
          bring_to_top(ref_name, consume)
          @sm.pop
          @sm.push(binding_name)
        else
          # Referenced value not on stack -- push placeholder
          emit_push_int(0)
          @sm.push(binding_name)
        end
        return
      end

      # Handle @this marker -- compile-time concept, not a runtime value
      if value.const_string == "@this"
        emit_push_int(0)
        @sm.push(binding_name)
        return
      end

      if !value.const_bool.nil?
        emit_push_bool(value.const_bool)
        @const_values[binding_name] = value.const_bool
      elsif !value.const_int.nil?
        emit_push_int(value.const_int)
        @const_values[binding_name] = value.const_int
      elsif !value.const_string.nil?
        emit_push_bytes(RunarCompiler::Codegen.hex_to_bytes(value.const_string))
        @const_values[binding_name] = value.const_string
      else
        # Fallback: push 0
        emit_push_int(0)
      end
      @sm.push(binding_name)
    end

    # Look up a compile-time constant value by binding name.
    #
    # @param binding_name [String]
    # @return [Object, nil] the constant value, or nil if not a constant
    def get_constant_value(binding_name)
      @const_values[binding_name]
    end

    # -----------------------------------------------------------------
    # bin_op
    # -----------------------------------------------------------------

    def _lower_bin_op(binding_name, op, left, right, binding_index, last_uses, result_type)
      left_is_last = _is_last_use(left, binding_index, last_uses)
      bring_to_top(left, left_is_last)

      right_is_last = _is_last_use(right, binding_index, last_uses)
      bring_to_top(right, right_is_last)

      @sm.pop
      @sm.pop

      # For equality operators, choose OP_EQUAL vs OP_NUMEQUAL based on operand type
      if result_type == "bytes" && %w[=== !==].include?(op)
        emit_opcode("OP_EQUAL")
        emit_opcode("OP_NOT") if op == "!=="
      elsif result_type == "bytes" && op == "+"
        # ByteString concatenation: + on byte types emits OP_CAT, not OP_ADD.
        emit_opcode("OP_CAT")
      else
        opcodes = BINOP_OPCODES[op]
        raise "unknown binary operator: #{op}" if opcodes.nil?

        opcodes.each { |code| emit_opcode(code) }
      end

      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # unary_op
    # -----------------------------------------------------------------

    def _lower_unary_op(binding_name, op, operand, binding_index, last_uses)
      is_last = _is_last_use(operand, binding_index, last_uses)
      bring_to_top(operand, is_last)
      @sm.pop

      opcodes = UNARYOP_OPCODES[op]
      raise "unknown unary operator: #{op}" if opcodes.nil?

      opcodes.each { |code| emit_opcode(code) }

      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # call
    # -----------------------------------------------------------------

    def _lower_call(binding_name, func_name, args, binding_index, last_uses)
      # Special handling for assert
      if func_name == "assert"
        if args && !args.empty?
          is_last = _is_last_use(args[0], binding_index, last_uses)
          bring_to_top(args[0], is_last)
          @sm.pop
          emit_opcode("OP_VERIFY")
          @sm.push(binding_name)
        end
        return
      end

      # exit(condition) => condition OP_VERIFY — same as assert
      if func_name == "exit"
        if args && !args.empty?
          is_last = _is_last_use(args[0], binding_index, last_uses)
          bring_to_top(args[0], is_last)
          @sm.pop
          emit_opcode("OP_VERIFY")
          @sm.push(binding_name)
        end
        return
      end

      # super() in constructor
      if func_name == "super"
        @sm.push(binding_name)
        return
      end

      # checkMultiSig(sigs, pks) -- special handling for OP_CHECKMULTISIG.
      if func_name == "checkMultiSig" && args.length == 2
        _lower_check_multi_sig(binding_name, args, binding_index, last_uses)
        return
      end

      # reverseBytes
      if func_name == "reverseBytes"
        _lower_reverse_bytes(binding_name, args, binding_index, last_uses)
        return
      end

      # substr
      if func_name == "substr"
        _lower_substr(binding_name, args, binding_index, last_uses)
        return
      end

      # WOTS+
      if func_name == "verifyWOTS"
        _lower_verify_wots(binding_name, args, binding_index, last_uses)
        return
      end

      # SLH-DSA
      if func_name.start_with?("verifySLHDSA_SHA2_")
        param_key = func_name["verifySLHDSA_".length..]
        _lower_verify_slh_dsa(binding_name, param_key, args, binding_index, last_uses)
        return
      end

      # SHA-256 partial verification builtins
      if func_name == "sha256Compress"
        _lower_sha256_compress(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "sha256Finalize"
        _lower_sha256_finalize(binding_name, args, binding_index, last_uses)
        return
      end

      # BLAKE3 builtins
      if func_name == "blake3Compress"
        _lower_blake3_compress(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "blake3Hash"
        _lower_blake3_hash(binding_name, args, binding_index, last_uses)
        return
      end

      # EC builtins
      if RunarCompiler::Codegen.ec_builtin?(func_name)
        _lower_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # NIST EC builtins (P-256 / P-384)
      if RunarCompiler::Codegen.nist_ec_builtin?(func_name)
        _lower_nist_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # ECDSA verification builtins
      if RunarCompiler::Codegen.verify_ecdsa_builtin?(func_name)
        _lower_verify_ecdsa(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # Baby Bear field arithmetic builtins
      if RunarCompiler::Codegen.bb_builtin?(func_name)
        _lower_bb_builtin(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # KoalaBear field arithmetic builtins
      if RunarCompiler::Codegen.kb_builtin?(func_name)
        _lower_kb_builtin(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # BN254 field arithmetic and G1 curve builtins
      if RunarCompiler::Codegen.bn254_builtin?(func_name)
        _lower_bn254_builtin(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # Poseidon2 KoalaBear Merkle root
      if func_name == "merkleRootPoseidon2KB"
        _lower_merkle_root_poseidon2_kb(binding_name, args, binding_index, last_uses)
        return
      end

      # Merkle proof verification builtins
      if RunarCompiler::Codegen.merkle_builtin?(func_name)
        _lower_merkle_root(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # Rabin signature verification
      if func_name == "verifyRabinSig"
        _lower_verify_rabin_sig(binding_name, args, binding_index, last_uses)
        return
      end

      # Math builtins with specialized lowering
      if %w[safediv safemod].include?(func_name)
        _lower_safe_div_mod(binding_name, func_name, args, binding_index, last_uses)
        return
      end
      if func_name == "clamp"
        _lower_clamp(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "pow"
        _lower_pow(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "mulDiv"
        _lower_mul_div(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "percentOf"
        _lower_percent_of(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "sqrt"
        _lower_sqrt(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "gcd"
        _lower_gcd(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "divmod"
        _lower_divmod(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "log2"
        _lower_log2(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "sign"
        _lower_sign(binding_name, args, binding_index, last_uses)
        return
      end
      if func_name == "right"
        _lower_right(binding_name, args, binding_index, last_uses)
        return
      end

      # pack() and toByteString() are type-level casts -- no-ops at the script level
      if %w[pack toByteString].include?(func_name)
        if args && !args.empty?
          arg = args[0]
          is_last = _is_last_use(arg, binding_index, last_uses)
          bring_to_top(arg, is_last)
          @sm.pop
          @sm.push(binding_name)
        end
        return
      end

      # computeStateOutputHash(preimage, stateBytes)
      if func_name == "computeStateOutputHash"
        _lower_compute_state_output_hash(binding_name, args, binding_index, last_uses)
        return
      end

      # computeStateOutput(preimage, stateBytes, newAmount)
      if func_name == "computeStateOutput"
        _lower_compute_state_output(binding_name, args, binding_index, last_uses)
        return
      end

      # buildChangeOutput(pkh, amount)
      if func_name == "buildChangeOutput"
        _lower_build_change_output(binding_name, args, binding_index, last_uses)
        return
      end

      # Preimage field extractors
      if func_name.length > 7 && func_name[0, 7] == "extract"
        _lower_extractor(binding_name, func_name, args, binding_index, last_uses)
        return
      end

      # General builtin: push args in order, then emit opcodes
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end

      # Pop all args
      args.length.times { @sm.pop }

      opcodes = BUILTIN_OPCODES[func_name]
      if opcodes.nil?
        # Unknown function -- push placeholder
        emit_push_int(0)
        @sm.push(binding_name)
        return
      end

      opcodes.each { |code| emit_opcode(code) }

      # Some builtins produce two outputs
      if func_name == "split"
        @sm.push("")           # left part
        @sm.push(binding_name) # right part (top)
      elsif func_name == "len"
        emit_opcode("OP_NIP")  # remove original value, keep only size
        @sm.push(binding_name)
      else
        @sm.push(binding_name)
      end

      _track_depth
    end

    # -----------------------------------------------------------------
    # method_call
    # -----------------------------------------------------------------

    def _lower_method_call(binding_name, obj, method_name, args, binding_index, last_uses)
      if method_name == "getStateScript"
        # Consume the @this object reference
        if @sm.has?(obj)
          bring_to_top(obj, true)
          emit_op({ op: "drop" })
          @sm.pop
        end
        _lower_get_state_script(binding_name)
        return
      end

      # Check if this is a private method call that should be inlined
      private_method = @private_methods[method_name]
      if private_method
        # Consume the @this object reference
        if @sm.has?(obj)
          bring_to_top(obj, true)
          emit_op({ op: "drop" })
          @sm.pop
        end
        _inline_method_call(binding_name, private_method, args, binding_index, last_uses)
        return
      end

      # For other method calls, treat like a function call
      _lower_call(binding_name, method_name, args, binding_index, last_uses)
    end

    def _inline_method_call(binding_name, method, args, binding_index, last_uses)
      # Track shadowed names so we can restore them after the body runs.
      shadowed = []

      # Bring all args to top and rename them to the method param names
      args.each_with_index do |arg, i|
        next unless i < method.params.length

        param_name = method.params[i].name
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
        @sm.pop

        # If param_name already exists on the stack, temporarily rename
        if @sm.has?(param_name)
          existing_depth = @sm.find_depth(param_name)
          shadowed_name = "__shadowed_#{binding_index}_#{param_name}"
          @sm.rename_at_depth(existing_depth, shadowed_name)
          shadowed << { param_name: param_name, shadowed_name: shadowed_name }
        end

        @sm.push(param_name)
      end

      # Lower the method body
      lower_bindings(method.body, false)

      # Restore shadowed names
      shadowed.each do |entry|
        sn = entry[:shadowed_name]
        pn = entry[:param_name]
        if @sm.has?(sn)
          depth = @sm.find_depth(sn)
          @sm.rename_at_depth(depth, pn)
        end
      end

      # The last binding's result should be on top of the stack.
      # Rename it to the calling binding name.
      if method.body && !method.body.empty?
        last_binding_name = method.body.last.name
        if @sm.depth > 0
          top_name = @sm.peek_at_depth(0)
          if top_name == last_binding_name
            @sm.pop
            @sm.push(binding_name)
          end
        end
      end
    end

    # -----------------------------------------------------------------
    # if (basic structure -- full implementation in Part 2)
    # -----------------------------------------------------------------

    def _lower_if(binding_name, cond, then_bindings, else_bindings, binding_index, last_uses, terminal_assert = false)
      then_bindings ||= []
      else_bindings ||= []

      is_last = _is_last_use(cond, binding_index, last_uses)
      bring_to_top(cond, is_last)
      @sm.pop # OP_IF consumes the condition

      # Identify parent-scope items still needed after this if-expression.
      protected_refs = Set.new
      last_uses.each do |ref, last_idx|
        protected_refs.add(ref) if last_idx > binding_index && @sm.has?(ref)
      end

      # Snapshot parent stackMap names before branches run
      pre_if_names = @sm.named_slots

      # Lower then-branch
      then_ctx = LoweringContext.new(nil, @properties)
      then_ctx.sm = @sm.clone
      then_ctx.outer_protected_refs = protected_refs
      then_ctx.inside_branch = true
      then_ctx.private_methods = @private_methods
      then_ctx.lower_bindings(then_bindings, terminal_assert)

      if terminal_assert && then_ctx.sm.depth > 1
        excess = then_ctx.sm.depth - 1
        excess.times do
          then_ctx.emit_op({ op: "nip" })
          then_ctx.sm.remove_at_depth(1)
        end
      end

      # Lower else-branch
      else_ctx = LoweringContext.new(nil, @properties)
      else_ctx.sm = @sm.clone
      else_ctx.outer_protected_refs = protected_refs
      else_ctx.inside_branch = true
      else_ctx.private_methods = @private_methods
      else_ctx.lower_bindings(else_bindings, terminal_assert)

      if terminal_assert && else_ctx.sm.depth > 1
        excess = else_ctx.sm.depth - 1
        excess.times do
          else_ctx.emit_op({ op: "nip" })
          else_ctx.sm.remove_at_depth(1)
        end
      end

      # Balance stack between branches
      post_then_names = then_ctx.sm.named_slots
      consumed_names = pre_if_names.select { |n| !post_then_names.include?(n) && else_ctx.sm.has?(n) }.to_a
      post_else_names = else_ctx.sm.named_slots
      else_consumed_names = pre_if_names.select { |n| !post_else_names.include?(n) && then_ctx.sm.has?(n) }.to_a

      # Phase 2: perform ALL drops before any placeholder pushes.
      if consumed_names.any?
        depths = consumed_names.map { |n| else_ctx.sm.find_depth(n) }.sort.reverse
        depths.each do |d|
          if d == 0
            else_ctx.emit_op({ op: "drop" })
            else_ctx.sm.pop
          elsif d == 1
            else_ctx.emit_op({ op: "nip" })
            else_ctx.sm.remove_at_depth(1)
          else
            else_ctx.emit_op({ op: "push", value: RunarCompiler::Codegen.big_int_push(d) })
            else_ctx.sm.push("")
            else_ctx.emit_op({ op: "roll", depth: d })
            else_ctx.sm.pop
            rolled = else_ctx.sm.remove_at_depth(d)
            else_ctx.sm.push(rolled)
            else_ctx.emit_op({ op: "drop" })
            else_ctx.sm.pop
          end
        end
      end
      if else_consumed_names.any?
        depths = else_consumed_names.map { |n| then_ctx.sm.find_depth(n) }.sort.reverse
        depths.each do |d|
          if d == 0
            then_ctx.emit_op({ op: "drop" })
            then_ctx.sm.pop
          elsif d == 1
            then_ctx.emit_op({ op: "nip" })
            then_ctx.sm.remove_at_depth(1)
          else
            then_ctx.emit_op({ op: "push", value: RunarCompiler::Codegen.big_int_push(d) })
            then_ctx.sm.push("")
            then_ctx.emit_op({ op: "roll", depth: d })
            then_ctx.sm.pop
            rolled = then_ctx.sm.remove_at_depth(d)
            then_ctx.sm.push(rolled)
            then_ctx.emit_op({ op: "drop" })
            then_ctx.sm.pop
          end
        end
      end

      # Phase 3: single depth-balance check after ALL drops.
      if then_ctx.sm.depth > else_ctx.sm.depth
        then_top_p3 = then_ctx.sm.peek_at_depth(0)
        if else_bindings.empty? && then_top_p3 && !then_top_p3.empty? && else_ctx.sm.has?(then_top_p3)
          var_depth = else_ctx.sm.find_depth(then_top_p3)
          if var_depth == 0
            else_ctx.emit_op({ op: "dup" })
          else
            else_ctx.emit_op({ op: "push", value: RunarCompiler::Codegen.big_int_push(var_depth) })
            else_ctx.sm.push("")
            else_ctx.emit_op({ op: "pick", depth: var_depth })
            else_ctx.sm.pop
          end
          else_ctx.sm.push(then_top_p3)
        else
          else_ctx.emit_op({ op: "push", value: { kind: "bytes", bytes_val: "".b } })
          else_ctx.sm.push("")
        end
      elsif else_ctx.sm.depth > then_ctx.sm.depth
        then_ctx.emit_op({ op: "push", value: { kind: "bytes", bytes_val: "".b } })
        then_ctx.sm.push("")
      end

      then_ops = then_ctx.ops
      else_ops = else_ctx.ops

      if_op = { op: "if", then: then_ops }
      if_op[:else_ops] = else_ops if else_ops.any?
      emit_op(if_op)

      # Reconcile parent stackMap
      post_branch_names = then_ctx.sm.named_slots
      pre_if_names.each do |n|
        if !post_branch_names.include?(n) && @sm.has?(n)
          depth = @sm.find_depth(n)
          @sm.remove_at_depth(depth)
        end
      end

      # The if expression may produce a result value on top.
      if then_ctx.sm.depth > @sm.depth
        then_top = then_ctx.sm.peek_at_depth(0)
        else_top = else_ctx.sm.depth > 0 ? else_ctx.sm.peek_at_depth(0) : ""
        is_property = @properties.any? { |p| p.name == then_top }
        if is_property && then_top && then_top == else_top && then_top != binding_name && @sm.has?(then_top)
          # Both branches did update_prop for the same property
          @sm.push(then_top)
          (1...@sm.depth).each do |d|
            next unless @sm.peek_at_depth(d) == then_top

            if d == 1
              emit_op({ op: "nip" })
              @sm.remove_at_depth(1)
            else
              emit_push_int(d)
              @sm.push("")
              emit_op({ op: "roll", depth: d + 1 })
              @sm.pop
              rolled = @sm.remove_at_depth(d)
              @sm.push(rolled)
              emit_op({ op: "drop" })
              @sm.pop
            end
            break
          end
        elsif then_top && !is_property && else_bindings.empty? && then_top != binding_name && @sm.has?(then_top)
          # If-without-else: then-branch reassigned a local variable
          @sm.push(then_top)
          (1...@sm.depth).each do |d|
            next unless @sm.peek_at_depth(d) == then_top

            if d == 1
              emit_op({ op: "nip" })
              @sm.remove_at_depth(1)
            else
              emit_push_int(d)
              @sm.push("")
              emit_op({ op: "roll", depth: d + 1 })
              @sm.pop
              rolled = @sm.remove_at_depth(d)
              @sm.push(rolled)
              emit_op({ op: "drop" })
              @sm.pop
            end
            break
          end
        else
          @sm.push(binding_name)
        end
      elsif else_ctx.sm.depth > @sm.depth
        @sm.push(binding_name)
      end
      # Void if -- don't push phantom

      _track_depth

      @max_depth = then_ctx.max_depth if then_ctx.max_depth > @max_depth
      @max_depth = else_ctx.max_depth if else_ctx.max_depth > @max_depth
    end

    # -----------------------------------------------------------------
    # loop
    # -----------------------------------------------------------------

    def _lower_loop(binding_name, count, body, iter_var)
      body ||= []
      count ||= 0

      # Collect body binding names
      body_binding_names = {}
      body.each { |b| body_binding_names[b.name] = true }

      # Collect outer-scope names referenced in the loop body
      outer_refs = Set.new
      body.each do |b|
        if b.value.kind == "load_param" && b.value.name != iter_var
          outer_refs.add(b.value.name)
        end
        if b.value.kind == "load_const" && b.value.const_string &&
           b.value.const_string.length > 5 && b.value.const_string[0, 5] == "@ref:"
          ref_name = b.value.const_string[5..]
          outer_refs.add(ref_name) unless body_binding_names[ref_name]
        end
      end

      # Temporarily extend localBindings with body binding names
      prev_local_bindings = @local_bindings
      new_local_bindings = prev_local_bindings.dup
      new_local_bindings.merge!(body_binding_names)
      @local_bindings = new_local_bindings

      count.times do |i|
        emit_push_int(i)
        @sm.push(iter_var)

        lu = RunarCompiler::Codegen.compute_last_uses(body)

        # In non-final iterations, prevent outer-scope refs from being consumed
        if i < count - 1
          outer_refs.each { |ref_name| lu[ref_name] = body.length }
        end

        body.each_with_index do |b, j|
          lower_binding(b, j, lu)
        end

        # Clean up the iteration variable if it was not consumed
        if @sm.has?(iter_var)
          depth = @sm.find_depth(iter_var)
          if depth == 0
            emit_op({ op: "drop" })
            @sm.pop
          end
        end
      end

      # Restore localBindings
      @local_bindings = prev_local_bindings

      # NOTE: loops are statements, not expressions -- they don't produce a
      # physical stack value.  Do NOT push a dummy stackMap entry.
      _ = binding_name
      _track_depth
    end

    # -----------------------------------------------------------------
    # assert
    # -----------------------------------------------------------------

    def _lower_assert(value_ref, binding_index, last_uses, terminal)
      is_last = _is_last_use(value_ref, binding_index, last_uses)
      bring_to_top(value_ref, is_last)
      unless terminal
        # Non-terminal assert: verify and consume
        @sm.pop
        emit_opcode("OP_VERIFY")
      end
      # Terminal assert: leave value on stack for Bitcoin Script's
      # final truthiness check.
      _track_depth
    end

    # -----------------------------------------------------------------
    # update_prop
    # -----------------------------------------------------------------

    def _lower_update_prop(prop_name, value_ref, binding_index, last_uses)
      is_last = _is_last_use(value_ref, binding_index, last_uses)
      bring_to_top(value_ref, is_last)
      @sm.pop
      @sm.push(prop_name)

      # When NOT inside an if-branch, remove the old property entry from
      # the stack.
      unless @inside_branch
        (1...@sm.depth).each do |d|
          next unless @sm.peek_at_depth(d) == prop_name

          if d == 1
            emit_op({ op: "nip" })
            @sm.remove_at_depth(1)
          else
            emit_push_int(d)
            @sm.push("")
            emit_op({ op: "roll", depth: d + 1 })
            @sm.pop
            rolled = @sm.remove_at_depth(d)
            @sm.push(rolled)
            emit_op({ op: "drop" })
            @sm.pop
          end
          break
        end
      end

      _track_depth
    end

    # -----------------------------------------------------------------
    # get_state_script (used by method_call for getStateScript)
    # -----------------------------------------------------------------

    def _lower_get_state_script(binding_name)
      state_props = @properties.select { |p| !p.readonly }

      if state_props.empty?
        emit_push_bytes("".b)
        @sm.push(binding_name)
        return
      end

      first = true
      state_props.each do |prop|
        if @sm.has?(prop.name)
          bring_to_top(prop.name, true) # consume
        elsif !prop.initial_value.nil?
          _push_property_value(prop.initial_value)
          @sm.push("")
        else
          emit_push_int(0)
          @sm.push("")
        end

        # Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
        case prop.type
        when "bigint"
          emit_push_int(8)
          @sm.push("")
          emit_opcode("OP_NUM2BIN")
          @sm.pop # pop the width
        when "boolean"
          emit_push_int(1)
          @sm.push("")
          emit_opcode("OP_NUM2BIN")
          @sm.pop # pop the width
        when "ByteString"
          # Prepend push-data length prefix (matching SDK format)
          emit_push_data_encode
        end

        unless first
          @sm.pop
          @sm.pop
          emit_opcode("OP_CAT")
          @sm.push("")
        end
        first = false
      end

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # Specialized call lowering
    # -----------------------------------------------------------------

    def _lower_check_multi_sig(binding_name, args, binding_index, last_uses)
      raise "checkMultiSig expects 2 arguments" unless args.length == 2

      sigs_ref = args[0]
      pks_ref = args[1]
      n_sigs = @array_lengths[sigs_ref] || 1
      n_pks = @array_lengths[pks_ref] || 1

      # Push OP_0 dummy (required by Bitcoin's OP_CHECKMULTISIG bug)
      emit_op({ op: "push", value: 0 })
      @sm.push(nil)

      # Bring sigs array to top
      bring_to_top(sigs_ref, _is_last_use(sigs_ref, binding_index, last_uses))

      # Push nSigs count
      emit_op({ op: "push", value: n_sigs })
      @sm.push(nil)

      # Bring pubkeys array to top
      bring_to_top(pks_ref, _is_last_use(pks_ref, binding_index, last_uses))

      # Push nPKs count
      emit_op({ op: "push", value: n_pks })
      @sm.push(nil)

      # Pop everything: OP_0 + sigs + nSigs + pks + nPKs
      5.times { @sm.pop }

      emit_opcode("OP_CHECKMULTISIG")
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_reverse_bytes(binding_name, args, binding_index, last_uses)
      raise "reverseBytes requires 1 argument" unless args.length == 1

      # Bring data to top of stack
      is_last = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last)
      @sm.pop

      # Push OP_0 as empty accumulator
      emit_op({ op: "push", value: 0 })
      @sm.push(nil)

      # Swap so data is on top: stack = [result, data]
      emit_op({ op: "swap" })
      @sm.swap

      # 520-iteration unrolled loop
      520.times do
        # DUP data
        emit_op({ op: "dup" })
        # OP_SIZE -> [result, data, data, len]
        emit_opcode("OP_SIZE")
        # NIP -> [result, data, len]
        emit_op({ op: "nip" })
        # IF len > 0
        emit_op({ op: "if", then: [
          { op: "push", value: { kind: "bigint", big_int: 1 } },
          { op: "opcode", code: "OP_SPLIT" },
          { op: "swap" },
          { op: "rot" },
          { op: "opcode", code: "OP_CAT" },
          { op: "swap" },
        ] })
      end

      # DROP the empty remainder
      emit_op({ op: "drop" })
      @sm.pop

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_substr(binding_name, args, binding_index, last_uses)
      raise "substr requires 3 arguments" if args.length < 3

      data, start, length = args[0], args[1], args[2]

      bring_to_top(data, _is_last_use(data, binding_index, last_uses))
      bring_to_top(start, _is_last_use(start, binding_index, last_uses))

      # Split at start position
      @sm.pop; @sm.pop
      emit_opcode("OP_SPLIT")
      @sm.push("")  # left (discard)
      @sm.push("")  # right (keep)

      # NIP
      emit_op({ op: "nip" })
      @sm.pop
      right_part = @sm.pop
      @sm.push(right_part)

      # Push length
      bring_to_top(length, _is_last_use(length, binding_index, last_uses))

      # Split at length
      @sm.pop; @sm.pop
      emit_opcode("OP_SPLIT")
      @sm.push("")  # result (keep)
      @sm.push("")  # remainder (discard)

      # DROP remainder
      emit_op({ op: "drop" })
      @sm.pop; @sm.pop

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_verify_wots(binding_name, args, binding_index, last_uses)
      require_relative "slh_dsa"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      SLHDSA.emit_verify_wots(emit_fn)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_verify_slh_dsa(binding_name, param_key, args, binding_index, last_uses)
      require_relative "slh_dsa"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      SLHDSA.emit_verify_slh_dsa(emit_fn, param_key)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_sha256_compress(binding_name, args, binding_index, last_uses)
      require_relative "sha256"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      SHA256Codegen.emit_sha256_compress(emit_fn)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_sha256_finalize(binding_name, args, binding_index, last_uses)
      require_relative "sha256"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      SHA256Codegen.emit_sha256_finalize(emit_fn)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_blake3_compress(binding_name, args, binding_index, last_uses)
      require_relative "blake3"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      Blake3.emit_blake3_compress(emit_fn)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_blake3_hash(binding_name, args, binding_index, last_uses)
      require_relative "blake3"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }
      emit_fn = ->(op) { emit_op(op) }
      Blake3.emit_blake3_hash(emit_fn)
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
      require_relative "ec"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      EC.dispatch_ec_builtin(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_nist_ec_builtin(binding_name, func_name, args, binding_index, last_uses)
      require_relative "p256_p384"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      NISTEC.dispatch_nist_ec_builtin(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_verify_ecdsa(binding_name, func_name, args, binding_index, last_uses)
      require_relative "p256_p384"
      if args.length < 3
        raise "#{func_name} requires 3 arguments: msg, sig, pubkey"
      end
      # Bring all 3 args to top in order: msg, sig, pubkey
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      @sm.pop # pubkey
      @sm.pop # sig
      @sm.pop # msg

      emit_fn = ->(op) { emit_op(op) }
      NISTEC.dispatch_verify_ecdsa(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_bb_builtin(binding_name, func_name, args, binding_index, last_uses)
      require_relative "babybear"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      BabyBear.dispatch_bb_builtin(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_kb_builtin(binding_name, func_name, args, binding_index, last_uses)
      require_relative "koalabear"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      KoalaBear.dispatch_kb_builtin(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_bn254_builtin(binding_name, func_name, args, binding_index, last_uses)
      require_relative "bn254"
      args.each do |arg|
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      args.length.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      BN254.dispatch_bn254_builtin(func_name, emit_fn)

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_merkle_root_poseidon2_kb(binding_name, args, binding_index, last_uses)
      require_relative "poseidon2_merkle"
      # args: [leaf_0..leaf_7, sib0_0..sib0_7, ..., sib(D-1)_0..sib(D-1)_7, index, depth]
      # depth must be a compile-time constant (last argument)
      n_args = args.length
      raise "merkleRootPoseidon2KB requires at least 10 arguments, got #{n_args}" if n_args < 10

      # Extract depth constant from ANF binding (last arg)
      depth_arg = args[n_args - 1]
      depth_value = get_constant_value(depth_arg)
      if depth_value.nil? || !depth_value.is_a?(Integer)
        raise "merkleRootPoseidon2KB: depth (last argument) must be a compile-time constant " \
              "integer literal. Got a runtime value for '#{depth_arg}'."
      end
      depth = depth_value
      if depth < 1 || depth > 64
        raise "merkleRootPoseidon2KB: depth must be between 1 and 64, got #{depth}"
      end

      # Validate argument count: 8 leaf + depth*8 proof + 1 index + 1 depth
      expected_args = 8 + depth * 8 + 1 + 1
      unless n_args == expected_args
        raise "merkleRootPoseidon2KB: expected #{expected_args} arguments " \
              "(8 leaf + #{depth}*8 proof + index + depth), got #{n_args}"
      end

      # Remove depth from the real stack FIRST (compile-time constant, not runtime)
      if @sm.has?(depth_arg)
        bring_to_top(depth_arg, true)
        emit_op({ op: "drop" })
        @sm.pop
      end

      # Bring all runtime args (leaf*8 + proof*depth*8 + index) to stack top in order
      runtime_arg_count = n_args - 1 # all except depth
      runtime_arg_count.times do |i|
        arg = args[i]
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      # Pop all runtime args — the codegen consumes them and produces 8 results
      runtime_arg_count.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }
      Poseidon2Merkle.emit_poseidon2_merkle_root(emit_fn, depth)

      # The codegen leaves 8 elements on the stack (root_0..root_7, root_7 on top).
      # The type system returns a single bigint, so only root_7 (top) is accessible.
      # Drop the lower 7 elements with OP_NIP to keep the stack clean.
      7.times { emit_op({ op: "nip" }) }

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_merkle_root(binding_name, func_name, args, binding_index, last_uses)
      require_relative "merkle"
      # args: [leaf, proof, index, depth]
      # depth must be a compile-time constant
      raise "#{func_name} requires exactly 4 arguments (leaf, proof, index, depth)" if args.length != 4

      # Extract depth constant from ANF binding
      depth_arg = args[3]
      depth_value = get_constant_value(depth_arg)
      if depth_value.nil? || !depth_value.is_a?(Integer)
        raise "#{func_name}: depth (4th argument) must be a compile-time constant integer literal. " \
              "Got a runtime value for '#{depth_arg}'."
      end
      depth = depth_value
      if depth < 1 || depth > 64
        raise "#{func_name}: depth must be between 1 and 64, got #{depth}"
      end

      # Remove depth from the real stack FIRST (compile-time constant, not runtime).
      if @sm.has?(depth_arg)
        bring_to_top(depth_arg, true)
        emit_op({ op: "drop" })
        @sm.pop
      end

      # Bring leaf, proof, index to stack top for the codegen
      3.times do |i|
        arg = args[i]
        is_last = _is_last_use(arg, binding_index, last_uses)
        bring_to_top(arg, is_last)
      end
      # Pop the 3 args -- the codegen consumes them and produces 1 result
      3.times { @sm.pop }

      emit_fn = ->(op) { emit_op(op) }

      if func_name == "merkleRootSha256"
        Merkle.emit_merkle_root_sha256(emit_fn, depth)
      else
        Merkle.emit_merkle_root_hash256(emit_fn, depth)
      end

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_safe_div_mod(binding_name, func_name, args, binding_index, last_uses)
      # safediv(a, b) / safemod(a, b): assert b != 0, then div/mod
      raise "#{func_name} requires 2 arguments" if args.length < 2

      is_last_a = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_a)
      is_last_b = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_b)

      # DUP b, check non-zero, then divide/mod
      emit_opcode("OP_DUP"); @sm.push("")
      emit_opcode("OP_0NOTEQUAL")
      emit_opcode("OP_VERIFY")
      @sm.pop

      @sm.pop; @sm.pop
      emit_opcode(func_name == "safediv" ? "OP_DIV" : "OP_MOD")

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_clamp(binding_name, args, binding_index, last_uses)
      # clamp(val, lo, hi) -> min(max(val, lo), hi)
      raise "clamp requires 3 arguments" if args.length < 3

      bring_to_top(args[0], _is_last_use(args[0], binding_index, last_uses))
      bring_to_top(args[1], _is_last_use(args[1], binding_index, last_uses))

      @sm.pop; @sm.pop
      emit_opcode("OP_MAX"); @sm.push("")

      bring_to_top(args[2], _is_last_use(args[2], binding_index, last_uses))

      @sm.pop; @sm.pop
      emit_opcode("OP_MIN")

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_pow(binding_name, args, binding_index, last_uses)
      raise "pow requires 2 arguments" if args.length < 2

      is_last_base = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_base)
      is_last_exp = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_exp)

      @sm.pop; @sm.pop

      emit_op({ op: "swap" })                              # exp base
      emit_op({ op: "push", value: { kind: "bigint", big_int: 1 } })  # exp base 1(acc)

      max_pow_iterations = 32
      max_pow_iterations.times do |i|
        emit_op({ op: "push", value: { kind: "bigint", big_int: 2 } })
        emit_op({ op: "pick" })
        emit_op({ op: "push", value: { kind: "bigint", big_int: i } })
        emit_opcode("OP_GREATERTHAN")
        emit_op({ op: "if", then: [
          { op: "over" },
          { op: "opcode", code: "OP_MUL" },
        ] })
      end
      emit_op({ op: "nip" })  # exp result
      emit_op({ op: "nip" })  # result

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_mul_div(binding_name, args, binding_index, last_uses)
      raise "mulDiv requires 3 arguments" if args.length < 3

      is_last_a = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_a)
      is_last_b = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_b)

      @sm.pop; @sm.pop
      emit_opcode("OP_MUL"); @sm.push("")

      is_last_c = _is_last_use(args[2], binding_index, last_uses)
      bring_to_top(args[2], is_last_c)

      @sm.pop; @sm.pop
      emit_opcode("OP_DIV")

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_percent_of(binding_name, args, binding_index, last_uses)
      # percentOf(amount, bps) -> (amount * bps) / 10000
      raise "percentOf requires 2 arguments" if args.length < 2

      is_last_a = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_a)
      is_last_b = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_b)

      @sm.pop; @sm.pop
      emit_opcode("OP_MUL"); @sm.push("")

      emit_push_int(10_000); @sm.push("")

      @sm.pop; @sm.pop
      emit_opcode("OP_DIV")

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_sqrt(binding_name, args, binding_index, last_uses)
      raise "sqrt requires 1 argument" if args.empty?

      is_last = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last)
      @sm.pop

      emit_opcode("OP_DUP")

      # Build Newton iteration ops for the then-branch
      newton_ops = []
      newton_ops << { op: "opcode", code: "OP_DUP" }  # n guess(=n)

      sqrt_iterations = 16
      sqrt_iterations.times do
        newton_ops << { op: "over" }
        newton_ops << { op: "over" }
        newton_ops << { op: "opcode", code: "OP_DIV" }
        newton_ops << { op: "opcode", code: "OP_ADD" }
        newton_ops << { op: "push", value: { kind: "bigint", big_int: 2 } }
        newton_ops << { op: "opcode", code: "OP_DIV" }
      end

      newton_ops << { op: "nip" }  # result (drop n)

      emit_op({ op: "if", then: newton_ops })

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_gcd(binding_name, args, binding_index, last_uses)
      raise "gcd requires 2 arguments" if args.length < 2

      is_last_a = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_a)
      is_last_b = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_b)

      @sm.pop; @sm.pop

      # Stack: a b -> |a| |b|
      emit_opcode("OP_ABS")
      emit_op({ op: "swap" })
      emit_opcode("OP_ABS")
      emit_op({ op: "swap" })

      gcd_iterations = 256
      gcd_iterations.times do
        emit_opcode("OP_DUP")
        emit_opcode("OP_0NOTEQUAL")
        emit_op({ op: "if", then: [
          { op: "opcode", code: "OP_TUCK" },
          { op: "opcode", code: "OP_MOD" },
        ] })
      end

      emit_op({ op: "drop" })

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_divmod(binding_name, args, binding_index, last_uses)
      raise "divmod requires 2 arguments" if args.length < 2

      is_last_a = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last_a)
      is_last_b = _is_last_use(args[1], binding_index, last_uses)
      bring_to_top(args[1], is_last_b)

      @sm.pop; @sm.pop

      emit_opcode("OP_2DUP")
      emit_opcode("OP_DIV")
      emit_opcode("OP_ROT")
      emit_opcode("OP_ROT")
      emit_opcode("OP_MOD")
      emit_op({ op: "drop" })

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_log2(binding_name, args, binding_index, last_uses)
      raise "log2 requires 1 argument" if args.empty?

      is_last = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last)
      @sm.pop

      # Push counter = 0
      emit_op({ op: "push", value: { kind: "bigint", big_int: 0 } })

      log2_iterations = 64
      log2_iterations.times do
        emit_op({ op: "swap" })
        emit_opcode("OP_DUP")
        emit_op({ op: "push", value: { kind: "bigint", big_int: 1 } })
        emit_opcode("OP_GREATERTHAN")
        emit_op({ op: "if", then: [
          { op: "push", value: { kind: "bigint", big_int: 2 } },
          { op: "opcode", code: "OP_DIV" },
          { op: "swap" },
          { op: "opcode", code: "OP_1ADD" },
          { op: "swap" },
        ] })
        emit_op({ op: "swap" })
      end

      # Drop input, keep counter
      emit_op({ op: "nip" })

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_sign(binding_name, args, binding_index, last_uses)
      raise "sign requires 1 argument" if args.empty?

      is_last = _is_last_use(args[0], binding_index, last_uses)
      bring_to_top(args[0], is_last)
      @sm.pop

      emit_opcode("OP_DUP")
      emit_op({ op: "if", then: [
        { op: "opcode", code: "OP_DUP" },
        { op: "opcode", code: "OP_ABS" },
        { op: "swap" },
        { op: "opcode", code: "OP_DIV" },
      ] })

      @sm.push(binding_name)
      _track_depth
    end

    def _lower_right(binding_name, args, binding_index, last_uses)
      # right(bs, n) -> last n bytes of bs
      if args.length >= 2
        is_last_bs = _is_last_use(args[0], binding_index, last_uses)
        bring_to_top(args[0], is_last_bs)
        is_last_n = _is_last_use(args[1], binding_index, last_uses)
        bring_to_top(args[1], is_last_n)

        # Stack: [bs, n]
        # Compute skip = SIZE - n, then SPLIT, NIP
        emit_op({ op: "swap" }); @sm.swap
        emit_opcode("OP_SIZE")
        @sm.push("")
        # Stack: [n, bs, size]
        emit_op({ op: "rot" })
        # Stack: [bs, size, n]
        temp = @sm.remove_at_depth(2)
        @sm.push(temp)
        emit_opcode("OP_SUB")
        @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT")
        @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" })
        @sm.remove_at_depth(1)
        @sm.pop
      end
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # check_preimage (OP_PUSH_TX)
    # -----------------------------------------------------------------

    def _lower_check_preimage(binding_name, preimage, binding_index, last_uses)
      # Step 0: Emit OP_CODESEPARATOR
      emit_opcode("OP_CODESEPARATOR")

      # Step 1: Bring preimage to top
      is_last = _is_last_use(preimage, binding_index, last_uses)
      bring_to_top(preimage, is_last)

      # Step 2: Bring _opPushTxSig to top (consuming)
      bring_to_top("_opPushTxSig", true)

      # Step 3: Push compressed secp256k1 generator point G (33 bytes)
      g_bytes = [
        0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB,
        0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28,
        0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98,
      ].pack("C*")
      emit_push_bytes(g_bytes)
      @sm.push("")

      # Step 4: OP_CHECKSIGVERIFY
      emit_opcode("OP_CHECKSIGVERIFY")
      @sm.pop # G consumed
      @sm.pop # _opPushTxSig consumed

      # Preimage remains on top. Rename for field extractors.
      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # Preimage field extractors
    # -----------------------------------------------------------------

    def _lower_extractor(binding_name, func_name, args, binding_index, last_uses)
      raise "#{func_name} requires 1 argument" if args.nil? || args.empty?

      arg = args[0]
      is_last = _is_last_use(arg, binding_index, last_uses)
      bring_to_top(arg, is_last)
      @sm.pop # consume the preimage from stack map

      case func_name
      when "extractVersion"
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_BIN2NUM")

      when "extractHashPrevouts"
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(32); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop

      when "extractHashSequence"
        emit_push_int(36); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(32); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop

      when "extractOutpoint"
        emit_push_int(68); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(36); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop

      when "extractSigHashType"
        emit_opcode("OP_SIZE"); @sm.push(""); @sm.push("")
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_BIN2NUM")

      when "extractLocktime"
        emit_opcode("OP_SIZE"); @sm.push(""); @sm.push("")
        emit_push_int(8); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_BIN2NUM")

      when "extractOutputHash", "extractOutputs"
        emit_opcode("OP_SIZE"); @sm.push(""); @sm.push("")
        emit_push_int(40); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(32); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop

      when "extractAmount"
        emit_opcode("OP_SIZE"); @sm.push(""); @sm.push("")
        emit_push_int(52); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(8); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_BIN2NUM")

      when "extractSequence"
        emit_opcode("OP_SIZE"); @sm.push(""); @sm.push("")
        emit_push_int(44); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_BIN2NUM")

      when "extractScriptCode"
        emit_push_int(104); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SIZE"); @sm.push("")
        emit_push_int(52); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop

      when "extractInputIndex"
        emit_push_int(100); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_push_int(4); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_BIN2NUM")

      else
        raise "unknown extractor: #{func_name}"
      end

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # get_state_script
    # -----------------------------------------------------------------

    def _lower_get_state_script(binding_name)
      state_props = @properties.reject(&:readonly)

      if state_props.empty?
        emit_push_bytes("".b)
        @sm.push(binding_name)
        return
      end

      first = true
      state_props.each do |prop|
        if @sm.has?(prop.name)
          bring_to_top(prop.name, true) # consume
        elsif !prop.initial_value.nil?
          _push_property_value(prop.initial_value)
          @sm.push("")
        else
          emit_push_int(0)
          @sm.push("")
        end

        # Convert numeric/boolean values to fixed-width bytes via OP_NUM2BIN
        if prop.type == "bigint"
          emit_push_int(8); @sm.push("")
          emit_opcode("OP_NUM2BIN"); @sm.pop
        elsif prop.type == "boolean"
          emit_push_int(1); @sm.push("")
          emit_opcode("OP_NUM2BIN"); @sm.pop
        elsif prop.type == "ByteString"
          emit_push_data_encode
        end

        unless first
          @sm.pop; @sm.pop
          emit_opcode("OP_CAT")
          @sm.push("")
        end
        first = false
      end

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # deserialize_state
    # -----------------------------------------------------------------

    def _lower_deserialize_state(preimage_ref, binding_index, last_uses)
      state_props = []
      prop_sizes = []
      has_variable_length = false

      @properties.each do |p|
        next if p.readonly

        state_props << p
        sz = case p.type
             when "bigint" then 8
             # RabinSig / RabinPubKey are bigint aliases — same 8-byte layout.
             when "RabinSig", "RabinPubKey" then 8
             when "boolean" then 1
             when "PubKey" then 33
             when "Addr" then 20
             # Ripemd160 is 20 bytes (same underlying shape as Addr).
             when "Ripemd160" then 20
             when "Sha256" then 32
             when "Point" then 64
             # P-256 point: x[32] || y[32] = 64 bytes (same shape as Point).
             when "P256Point" then 64
             # P-384 point: x[48] || y[48] = 96 bytes.
             when "P384Point" then 96
             # ByteString-typed variable-length fields — treated the same
             # as ByteString (push-data-prefixed in state).
             when "ByteString", "Sig", "SigHashPreimage"
               has_variable_length = true
               -1
             else
               raise "deserialize_state: unsupported type: #{p.type}"
             end
        prop_sizes << sz
      end

      return if state_props.empty?

      is_last = _is_last_use(preimage_ref, binding_index, last_uses)
      bring_to_top(preimage_ref, is_last)

      # 1. Skip first 104 bytes (header), drop prefix
      emit_push_int(104); @sm.push("")
      emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")

      # 2. Drop tail 44 bytes
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_push_int(44); @sm.push("")
      emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop

      # 3. Drop amount (last 8 bytes)
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop

      if !has_variable_length
        state_len = prop_sizes.sum

        # 4. Extract last stateLen bytes
        emit_opcode("OP_SIZE"); @sm.push("")
        emit_push_int(state_len); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")

        # 5. Split fixed-size fields
        _split_fixed_state_fields(state_props, prop_sizes)
      elsif !@sm.has?("_codePart")
        # Variable-length state but _codePart not available (terminal method)
        emit_op({ op: "drop" }); @sm.pop
      else
        # Variable-length path: strip varint, use _codePart to find state.
        #
        # BIP-143 scriptCode is prefixed by a Bitcoin varint:
        #   length < 0xfd:        1 byte (length itself)
        #   length <= 0xffff:     0xfd + 2 bytes LE                (3 bytes)
        #   length <= 0xffffffff: 0xfe + 4 bytes LE                (5 bytes)
        #   otherwise:            0xff + 8 bytes LE                (9 bytes)
        #
        # We must support all four shapes, otherwise scripts whose
        # scriptCode exceeds 65,535 bytes (e.g. embedded BN254 verifiers)
        # silently strip too few varint bytes and corrupt the subsequent
        # state-extraction OP_SPLITs — this surfaces as
        # `Invalid OP_SPLIT range` on regtest.
        emit_push_int(1); @sm.push("")
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "swap" }); @sm.swap
        # Zero-pad firstByte before BIN2NUM so 0xfd/0xfe/0xff aren't read
        # as negative script numbers.
        emit_push_bytes([0].pack("C"))
        @sm.push("")
        emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_BIN2NUM")
        # Stack: [..., rest, fb_num]

        # emit_drop_more_varint_bytes drops `n` additional varint bytes
        # from the top of stack `rest`. [..., rest] -> [..., rest_minus_n].
        emit_drop_more_varint_bytes = lambda do |n|
          emit_push_int(n); @sm.push("")
          emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
          emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        end

        # IF fb_num < 253: 1-byte varint, drop fb_num.
        emit_op({ op: "dup" }); @sm.dup
        emit_push_int(253); @sm.push("")
        emit_opcode("OP_LESSTHAN"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_IF"); @sm.pop
        sm_at_1byte_if = @sm.clone
        # THEN: 1-byte varint
        emit_op({ op: "drop" }); @sm.pop
        emit_opcode("OP_ELSE")
        @sm = sm_at_1byte_if.clone
        # ELSE: fb_num >= 253. Check 0xfe (5-byte varint) next.
        emit_op({ op: "dup" }); @sm.dup
        emit_push_int(254); @sm.push("")
        emit_opcode("OP_NUMEQUAL"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_IF"); @sm.pop
        sm_at_fe_if = @sm.clone
        # THEN: 5-byte varint (0xfe + 4 bytes LE).
        emit_op({ op: "drop" }); @sm.pop
        emit_drop_more_varint_bytes.call(4)
        emit_opcode("OP_ELSE")
        @sm = sm_at_fe_if.clone
        # ELSE: fb_num != 254. Check 0xff (9-byte varint) next.
        emit_op({ op: "dup" }); @sm.dup
        emit_push_int(255); @sm.push("")
        emit_opcode("OP_NUMEQUAL"); @sm.pop; @sm.pop; @sm.push("")
        emit_opcode("OP_IF"); @sm.pop
        sm_at_ff_if = @sm.clone
        # THEN: 9-byte varint (0xff + 8 bytes LE).
        emit_op({ op: "drop" }); @sm.pop
        emit_drop_more_varint_bytes.call(8)
        emit_opcode("OP_ELSE")
        @sm = sm_at_ff_if.clone
        # ELSE: fb_num must be 253 (0xfd) — 3-byte varint.
        emit_op({ op: "drop" }); @sm.pop
        emit_drop_more_varint_bytes.call(2)
        emit_opcode("OP_ENDIF")
        emit_opcode("OP_ENDIF")
        emit_opcode("OP_ENDIF")

        # Compute skip = SIZE(_codePart) - codeSepIdx
        bring_to_top("_codePart", false)
        emit_opcode("OP_SIZE"); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
        emit_op({ op: "push_codesep_index" }); @sm.push("")
        emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")

        # Split scriptCode at skip to get state
        emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
        emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")

        # Parse variable-length state fields
        _parse_variable_length_state_fields(state_props, prop_sizes)
      end

      _track_depth
    end

    def _split_fixed_state_fields(state_props, prop_sizes)
      if state_props.length == 1
        prop = state_props[0]
        emit_opcode("OP_BIN2NUM") if RunarCompiler::Codegen.numeric_state_type?(prop.type)
        @sm.pop
        @sm.push(prop.name)
      else
        state_props.each_with_index do |prop, i|
          sz = prop_sizes[i]
          if i < state_props.length - 1
            emit_push_int(sz); @sm.push("")
            emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
            emit_op({ op: "swap" }); @sm.swap
            emit_opcode("OP_BIN2NUM") if RunarCompiler::Codegen.numeric_state_type?(prop.type)
            emit_op({ op: "swap" }); @sm.swap
            @sm.pop; @sm.pop
            @sm.push(prop.name); @sm.push("")
          else
            emit_opcode("OP_BIN2NUM") if RunarCompiler::Codegen.numeric_state_type?(prop.type)
            @sm.pop
            @sm.push(prop.name)
          end
        end
      end
    end

    def _parse_variable_length_state_fields(state_props, prop_sizes)
      if state_props.length == 1
        prop = state_props[0]
        if RunarCompiler::Codegen.variable_length_state_type?(prop.type)
          emit_push_data_decode
          emit_op({ op: "drop" }); @sm.pop
        elsif RunarCompiler::Codegen.numeric_state_type?(prop.type)
          emit_opcode("OP_BIN2NUM")
        end
        @sm.pop
        @sm.push(prop.name)
      else
        state_props.each_with_index do |prop, i|
          if i < state_props.length - 1
            if RunarCompiler::Codegen.variable_length_state_type?(prop.type)
              emit_push_data_decode
              @sm.pop; @sm.pop
              @sm.push(prop.name); @sm.push("")
            else
              sz = prop_sizes[i]
              emit_push_int(sz); @sm.push("")
              emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
              emit_op({ op: "swap" }); @sm.swap
              emit_opcode("OP_BIN2NUM") if RunarCompiler::Codegen.numeric_state_type?(prop.type)
              emit_op({ op: "swap" }); @sm.swap
              @sm.pop; @sm.pop
              @sm.push(prop.name); @sm.push("")
            end
          else
            if RunarCompiler::Codegen.variable_length_state_type?(prop.type)
              emit_push_data_decode
              emit_op({ op: "drop" }); @sm.pop
            elsif RunarCompiler::Codegen.numeric_state_type?(prop.type)
              emit_opcode("OP_BIN2NUM")
            end
            @sm.pop
            @sm.push(prop.name)
          end
        end
      end
    end

    # -----------------------------------------------------------------
    # add_output
    # -----------------------------------------------------------------

    def _lower_add_output(binding_name, satoshis, state_values, _preimage, binding_index, last_uses)
      state_props = @properties.reject(&:readonly)

      # Step 1: Bring _codePart to top (PICK -- never consume)
      bring_to_top("_codePart", false)

      # Step 2: Append OP_RETURN byte (0x6a)
      emit_push_bytes([0x6A].pack("C"))
      @sm.push("")
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Step 3: Serialize each state value and concatenate
      (0...[state_values.length, state_props.length].min).each do |i|
        value_ref = state_values[i]
        prop = state_props[i]

        is_last = _is_last_use(value_ref, binding_index, last_uses)
        bring_to_top(value_ref, is_last)

        if prop.type == "bigint"
          emit_push_int(8); @sm.push("")
          emit_opcode("OP_NUM2BIN"); @sm.pop
        elsif prop.type == "boolean"
          emit_push_int(1); @sm.push("")
          emit_opcode("OP_NUM2BIN"); @sm.pop
        elsif prop.type == "ByteString"
          emit_push_data_encode
        end

        @sm.pop; @sm.pop
        emit_opcode("OP_CAT"); @sm.push("")
      end

      # Step 4: Compute varint prefix for the full script length
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_varint_encoding

      # Step 5: Prepend varint to script: SWAP CAT
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      # Step 6: Prepend satoshis as 8-byte LE
      is_last_sat = _is_last_use(satoshis, binding_index, last_uses)
      bring_to_top(satoshis, is_last_sat)
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_NUM2BIN"); @sm.pop
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # add_raw_output
    # -----------------------------------------------------------------

    def _lower_add_raw_output(binding_name, satoshis, script_bytes, binding_index, last_uses)
      # Step 1: Bring scriptBytes to top
      script_is_last = _is_last_use(script_bytes, binding_index, last_uses)
      bring_to_top(script_bytes, script_is_last)

      # Step 2: Compute varint prefix for script length
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_varint_encoding

      # Step 3: Prepend varint to script: SWAP CAT
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      # Step 4: Prepend satoshis as 8-byte LE
      sat_is_last = _is_last_use(satoshis, binding_index, last_uses)
      bring_to_top(satoshis, sat_is_last)
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_NUM2BIN"); @sm.pop
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # array_literal
    # -----------------------------------------------------------------

    def _lower_array_literal(binding_name, elements, binding_index, last_uses)
      @array_lengths[binding_name] = elements.length
      elements.each do |elem|
        is_last = _is_last_use(elem, binding_index, last_uses)
        bring_to_top(elem, is_last)
        @sm.pop
        @sm.push("") # anonymous stack entry for intermediate elements
      end
      @sm.pop if elements.any?
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # compute_state_output_hash
    # -----------------------------------------------------------------

    def _lower_compute_state_output_hash(binding_name, args, binding_index, last_uses)
      preimage_ref = args[0]
      state_bytes_ref = args[1]

      # Bring stateBytes to stack first
      state_last = _is_last_use(state_bytes_ref, binding_index, last_uses)
      bring_to_top(state_bytes_ref, state_last)

      # Extract amount from preimage for the continuation output
      pre_last = _is_last_use(preimage_ref, binding_index, last_uses)
      bring_to_top(preimage_ref, pre_last)

      # Extract amount: last 52 bytes, take 8 bytes at offset 0
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_push_int(52); @sm.push("")
      emit_opcode("OP_SUB"); @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "nip" }); @sm.pop; @sm.pop; @sm.push("")
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_SPLIT"); @sm.pop; @sm.pop; @sm.push(""); @sm.push("")
      emit_op({ op: "drop" }); @sm.pop

      # Save amount to altstack
      emit_opcode("OP_TOALTSTACK"); @sm.pop

      # Bring _codePart to top (PICK -- never consume)
      bring_to_top("_codePart", false)

      # Append OP_RETURN + stateBytes
      emit_push_bytes([0x6A].pack("C")); @sm.push("")
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Compute varint prefix for script length
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_varint_encoding

      # Prepend varint to script
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      # Prepend amount from altstack
      emit_opcode("OP_FROMALTSTACK"); @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Hash with SHA256d
      emit_opcode("OP_HASH256")

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # compute_state_output (raw bytes, no hash)
    # -----------------------------------------------------------------

    def _lower_compute_state_output(binding_name, args, binding_index, last_uses)
      preimage_ref = args[0]
      state_bytes_ref = args[1]
      new_amount_ref = args[2]

      # Consume preimage ref (no longer needed)
      pre_last = _is_last_use(preimage_ref, binding_index, last_uses)
      bring_to_top(preimage_ref, pre_last)
      emit_op({ op: "drop" }); @sm.pop

      # Step 1: Convert _newAmount to 8-byte LE and save to altstack
      amount_last = _is_last_use(new_amount_ref, binding_index, last_uses)
      bring_to_top(new_amount_ref, amount_last)
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_NUM2BIN"); @sm.pop; @sm.pop; @sm.push("")
      emit_opcode("OP_TOALTSTACK"); @sm.pop

      # Step 2: Bring stateBytes to stack
      state_last = _is_last_use(state_bytes_ref, binding_index, last_uses)
      bring_to_top(state_bytes_ref, state_last)

      # Step 3: Bring _codePart to top (PICK -- never consume)
      bring_to_top("_codePart", false)

      # Step 4: Append OP_RETURN + stateBytes
      emit_push_bytes([0x6A].pack("C")); @sm.push("")
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Step 5: Compute varint prefix for script length
      emit_opcode("OP_SIZE"); @sm.push("")
      emit_varint_encoding

      # Prepend varint to script
      emit_op({ op: "swap" }); @sm.swap
      @sm.pop; @sm.pop
      emit_opcode("OP_CAT"); @sm.push("")

      # Step 6: Prepend _newAmount (8-byte LE) from altstack
      emit_opcode("OP_FROMALTSTACK"); @sm.push("")
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    # -----------------------------------------------------------------
    # build_change_output
    # -----------------------------------------------------------------

    def _lower_build_change_output(binding_name, args, binding_index, last_uses)
      pkh_ref = args[0]
      amount_ref = args[1]

      # Step 1: Build P2PKH locking script with length prefix
      # Push prefix: varint(25) + OP_DUP + OP_HASH160 + OP_PUSHBYTES_20 = 0x1976a914
      emit_push_bytes([0x19, 0x76, 0xa9, 0x14].pack("C*"))
      @sm.push("")

      # Push the 20-byte PKH
      bring_to_top(pkh_ref, _is_last_use(pkh_ref, binding_index, last_uses))
      # CAT: prefix || pkh
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Push suffix: OP_EQUALVERIFY + OP_CHECKSIG = 0x88ac
      emit_push_bytes([0x88, 0xac].pack("C*"))
      @sm.push("")
      # CAT: (prefix || pkh) || suffix
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      # Step 2: Prepend amount as 8-byte LE
      bring_to_top(amount_ref, _is_last_use(amount_ref, binding_index, last_uses))
      emit_push_int(8); @sm.push("")
      emit_opcode("OP_NUM2BIN"); @sm.pop
      emit_op({ op: "swap" }); @sm.swap
      emit_opcode("OP_CAT"); @sm.pop; @sm.pop; @sm.push("")

      @sm.pop
      @sm.push(binding_name)
      _track_depth
    end

    def _lower_verify_rabin_sig(binding_name, args, binding_index, last_uses)
      raise "verifyRabinSig requires 4 arguments" if args.length < 4

      msg, sig, padding, pub_key = args[0], args[1], args[2], args[3]

      bring_to_top(msg, _is_last_use(msg, binding_index, last_uses))
      bring_to_top(sig, _is_last_use(sig, binding_index, last_uses))
      bring_to_top(padding, _is_last_use(padding, binding_index, last_uses))
      bring_to_top(pub_key, _is_last_use(pub_key, binding_index, last_uses))

      4.times { @sm.pop }

      # Rabin sig verification opcode sequence
      emit_opcode("OP_SWAP")
      emit_opcode("OP_ROT")
      emit_opcode("OP_DUP")
      emit_opcode("OP_MUL")
      emit_opcode("OP_ADD")
      emit_opcode("OP_SWAP")
      emit_opcode("OP_MOD")
      emit_opcode("OP_SWAP")
      emit_opcode("OP_SHA256")
      emit_opcode("OP_EQUAL")

      @sm.push(binding_name)
      _track_depth
    end
  end

  # -----------------------------------------------------------------------
  # Module-level entry points
  # -----------------------------------------------------------------------

  # Convert an ANF program to a list of StackMethod hashes.
  #
  # Private methods are inlined at call sites rather than compiled separately.
  # The constructor is skipped since it's not emitted to Bitcoin Script.
  #
  # @param program [IR::ANFProgram] the ANF program
  # @return [Array<Hash>] list of stack method hashes
  def self.lower_to_stack(program)
    _lower_to_stack_inner(program)
  rescue RuntimeError
    raise
  rescue => e
    raise RuntimeError, "stack lowering: #{e}"
  end

  # @api private
  def self._lower_to_stack_inner(program)
    # Build map of private methods for inlining
    private_methods = {}
    program.methods.each do |m|
      private_methods[m.name] = m if !m.is_public && m.name != "constructor"
    end

    methods = []
    program.methods.each do |method|
      # Skip constructor and private methods
      next if method.name == "constructor"
      next if !method.is_public && method.name != "constructor"

      sm = _lower_method_with_private_methods(method, program.properties, private_methods)
      methods << sm
    end

    methods
  end
  private_class_method :_lower_to_stack_inner

  # @api private
  def self._lower_method_with_private_methods(method, properties, private_methods)
    param_names = method.params.map(&:name)

    # If the method uses checkPreimage, the unlocking script pushes implicit
    # params before all declared parameters (OP_PUSH_TX pattern).
    if method_uses_check_preimage?(method.body)
      param_names = ["_opPushTxSig"] + param_names
      # _codePart is needed when the method has add_output or add_raw_output
      if method_uses_code_part?(method.body)
        param_names = ["_codePart"] + param_names
      end
    end

    ctx = LoweringContext.new(param_names, properties)
    ctx.private_methods = private_methods
    # Pass terminalAssert=true for public methods
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items left by deserialize_state.
    has_deserialize_state = method.body.any? { |b| b.value.kind == "deserialize_state" }
    if method.is_public && has_deserialize_state && ctx.sm.depth > 1
      excess = ctx.sm.depth - 1
      excess.times do
        ctx.emit_op({ op: "nip" })
        ctx.sm.remove_at_depth(1)
      end
    end

    if ctx.max_depth > MAX_STACK_DEPTH
      raise RuntimeError,
            "method '#{method.name}' exceeds maximum stack depth of #{MAX_STACK_DEPTH} " \
            "(actual: #{ctx.max_depth}). Simplify the contract logic"
    end

    { name: method.name, ops: ctx.ops, max_stack_depth: ctx.max_depth }
  end
  private_class_method :_lower_method_with_private_methods

  # Lower a single method (no private method inlining). Useful for testing.
  #
  # @api private
  def self.lower_method(method, properties)
    param_names = method.params.map(&:name)

    ctx = LoweringContext.new(param_names, properties)
    ctx.lower_bindings(method.body, method.is_public)

    # Clean up excess stack items left by deserialize_state.
    has_deserialize_state = method.body.any? { |b| b.value.kind == "deserialize_state" }
    if method.is_public && has_deserialize_state && ctx.sm.depth > 1
      excess = ctx.sm.depth - 1
      excess.times do
        ctx.emit_op({ op: "nip" })
        ctx.sm.remove_at_depth(1)
      end
    end

    if ctx.max_depth > MAX_STACK_DEPTH
      raise RuntimeError,
            "method '#{method.name}' exceeds maximum stack depth of #{MAX_STACK_DEPTH} " \
            "(actual: #{ctx.max_depth}). Simplify the contract logic"
    end

    { name: method.name, ops: ctx.ops, max_stack_depth: ctx.max_depth }
  end
  private_class_method :lower_method

  # --- CONTINUED IN PART 2 (lower_binding advanced kinds) ---
end
