# frozen_string_literal: true

# ANF IR type definitions for the Runar compiler.
#
# This module defines the A-Normal Form intermediate representation types.
# Direct port of compilers/python/runar_compiler/ir/types.py.
#
# Ruby Integer is already arbitrary-precision, so no special handling is needed
# for big integers.

require "json"

module RunarCompiler
  module IR
    # Name prefix for the temporaries ANF lowering appends to BOTH arms of an
    # if-statement that merges two or more locals.
    #
    # An +if+ carries one value, so post-branch references to a merged local can
    # only be rewired by aliasing when there is exactly ONE of them. For two or
    # more, both arms instead end with an identical K-binding block -- K copies
    # into +__merge$0..K-1+, then K rebinds of the locals from those temps --
    # which leaves the merged values on top in the same canonical order
    # whichever branch runs. Stack lowering recognises that trailing block by
    # this prefix, trims each arm down to the K results, and adopts them by
    # name.
    #
    # The prefix is part of the ANF wire format: all seven compilers emit and
    # recognise the same block.
    MERGED_LOCAL_TEMP_PREFIX = "__merge$"
    # -------------------------------------------------------------------
    # Source location
    # -------------------------------------------------------------------

    SourceLocation = Struct.new(:file, :line, :column, keyword_init: true) do
      def initialize(file: "", line: 0, column: 0)
        super(file: file, line: line, column: column)
      end
    end

    # -------------------------------------------------------------------
    # Program structure
    # -------------------------------------------------------------------

    # +parent_class+ is the base class the source contract extends
    # ("SmartContract" | "StatefulSmartContract" | "UnsafeSmartContract"). It is
    # an in-memory carrier ONLY -- it is never written into the emitted ANF IR
    # JSON that the conformance suite compares cross-tier (see
    # +_serialize_anf_program+ in compiler.rb, which omits it). The artifact
    # assembler copies it to the top-level artifact field so SDKs can gate the
    # issue-#42/#44 terminal sighash subscript trim on the authoritative parent
    # class (a StatefulSmartContract with zero mutable fields still needs the
    # trim even though stateFields is empty).
    ANFProgram = Struct.new(:contract_name, :properties, :methods, :parent_class, keyword_init: true) do
      def initialize(contract_name: "", properties: [], methods: [], parent_class: "")
        super(contract_name: contract_name, properties: properties, methods: methods, parent_class: parent_class)
      end
    end

    # +synthetic_array_chain+ propagates the +PropertyNode#synthetic_array_chain+
    # marker from the AST into the ANF IR so the artifact assembler can
    # iteratively re-group expanded +FixedArray<T, N>+ leaves back into a
    # logical +FixedArray+ state field.  Each entry is a Hash with keys
    # +:base+, +:index+, +:length+ (outermost first).  +nil+ on user-written
    # scalar properties.
    ANFProperty = Struct.new(:name, :type, :readonly, :initial_value, :synthetic_array_chain, keyword_init: true) do
      def initialize(name: "", type: "", readonly: false, initial_value: nil, synthetic_array_chain: nil)
        super(name: name, type: type, readonly: readonly, initial_value: initial_value, synthetic_array_chain: synthetic_array_chain)
      end
    end

    # +sighash_type+ carries the declared +@sighash+ mode (issue #123) from the
    # AST MethodNode so the artifact assembler can stamp a non-default mode into
    # the ABI +sigHashType+. Like +ANFProgram#parent_class+ it is an in-memory
    # carrier ONLY — it is never written into the emitted ANF IR JSON that the
    # conformance suite compares cross-tier (the ANF carries the mode instead on
    # the +check_preimage+ node's +sighash_flag+; see +_serialize_anf_program+).
    ANFMethod = Struct.new(:name, :params, :body, :is_public, :sighash_type, keyword_init: true) do
      def initialize(name: "", params: [], body: [], is_public: false, sighash_type: nil)
        super(name: name, params: params, body: body, is_public: is_public, sighash_type: sighash_type)
      end
    end

    ANFParam = Struct.new(:name, :type, keyword_init: true) do
      def initialize(name: "", type: "")
        super(name: name, type: type)
      end
    end

    # -------------------------------------------------------------------
    # Bindings -- the core of the ANF representation
    # -------------------------------------------------------------------

    ANFBinding = Struct.new(:name, :value, :source_loc, keyword_init: true) do
      def initialize(name: "", value: nil, source_loc: nil)
        super(name: name, value: value || ANFValue.new, source_loc: source_loc)
      end
    end

    # -------------------------------------------------------------------
    # ANF value types (discriminated on kind)
    # -------------------------------------------------------------------

    # Flat class with a +kind+ discriminator.
    #
    # Only the fields relevant to the specific kind are populated. This mirrors
    # the Go approach: a single struct rather than an interface hierarchy, which
    # keeps JSON round-tripping straightforward.
    class ANFValue
      attr_accessor :kind,
                    # -- load_param, load_prop, update_prop -----------------
                    :name,
                    # -- load_const: raw JSON value (kept for lossless round-trip)
                    :raw_value,
                    # -- Decoded constant value (populated by decode_constants)
                    :const_string,
                    :const_big_int,   # Ruby Integer is arbitrary-precision
                    :const_bool,
                    :const_int,       # small integers from JSON numbers
                    # -- bin_op ---------------------------------------------
                    :op,
                    :left,
                    :right,
                    :result_type,     # operand type hint: "bytes" for byte-typed equality
                    # -- unary_op ------------------------------------------
                    :operand,
                    # -- call ----------------------------------------------
                    :func,
                    :args,
                    # -- method_call ---------------------------------------
                    :object,
                    :method,
                    # -- if ------------------------------------------------
                    :cond,
                    :then,
                    :else_,
                    # Ordered named result slots both arms leave (results[0]
                    # deepest). Entries name a branch-merged local or an
                    # arm-written contract property; stack lowering tells the
                    # two apart from the contract's property list, so the wire
                    # format stays a plain array of strings. nil (not []) when
                    # the +if+ carries at most one result -- see the TypeScript
                    # reference in packages/runar-compiler/src/ir/anf-ir.ts for
                    # the full contract.
                    :results,
                    # -- loop ----------------------------------------------
                    :count,
                    :iter_var,
                    :body,
                    # Iterator start value (Integer) and step direction
                    # (+1 / -1) for non-zero-start & countdown loops (#121).
                    # On iteration +i+ the iterator holds +start + i*step+.
                    # Zero-start counting-up loops carry start=0, step=1,
                    # reproducing the historical i = 0..count-1 lowering.
                    :start,
                    :step,
                    # -- assert, update_prop (value ref), check_preimage ---
                    :value_ref,
                    # -- check_preimage, deserialize_state -----------------
                    :preimage,
                    # -- check_preimage: BIP-143 sighash flag the on-chain
                    #    OP_PUSH_TX binding appends to the derived signature
                    #    (issue #123). nil = default ALL|FORKID (0x41),
                    #    byte-identical to the pinned cross-tier binding blob.
                    :sighash_flag,
                    # -- check_preimage: the Any-S binding construction (nil/""/
                    #    "lowS" = default low-S blob, byte-identical to the pinned
                    #    cross-tier binding; "all" = the compact non-low-S blob).
                    #    Only set for a method that declares @bindingVariant all,
                    #    keeping golden ANF unchanged for every existing contract.
                    :binding_variant,
                    # -- add_output ----------------------------------------
                    :satoshis,
                    :state_values,
                    # -- add_raw_output ------------------------------------
                    :script_bytes,
                    # -- array_literal -------------------------------------
                    :elements,
                    # -- raw_script: opaque opcode-byte span with declared
                    #    stack arity (emitted by the asm() intrinsic).
                    :bytes,
                    :in_arity,
                    :out_arity,
                    # -- assert (auto-injected stateful-continuation marker) --
                    # +true+ only on the compiler-emitted
                    # +hash256(continuationOutputs) === extractOutputHash(txPreimage)+
                    # assert. Off-chain SDK interpreters skip this assert via a
                    # direct marker lookup instead of structural / taint
                    # heuristics that misfire on developer covenant asserts.
                    :is_auto_injected_state_check

      def initialize(kind: "", **_opts)
        @kind = kind
        @name = nil
        @raw_value = nil
        @const_string = nil
        @const_big_int = nil
        @const_bool = nil
        @const_int = nil
        @op = nil
        @left = nil
        @right = nil
        @result_type = nil
        @operand = nil
        @func = nil
        @args = nil
        @object = nil
        @method = nil
        @cond = nil
        @then = nil
        @else_ = nil
        @results = nil
        @count = nil
        @iter_var = nil
        @body = nil
        @start = nil
        @step = nil
        @value_ref = nil
        @preimage = nil
        @sighash_flag = nil
        @binding_variant = nil
        @satoshis = nil
        @state_values = nil
        @script_bytes = nil
        @elements = nil
        @bytes = nil
        @in_arity = nil
        @out_arity = nil
        @is_auto_injected_state_check = false
      end
    end

    # -------------------------------------------------------------------
    # Constant decoding
    # -------------------------------------------------------------------

    # Walk +program+ and decode +raw_value+ fields in +load_const+
    # bindings into their typed Ruby representations, and extract the value
    # reference string for +assert+ / +update_prop+ kinds.
    #
    # Raises +ArgumentError+ on decode failures.
    def self.decode_constants(program)
      program.methods.each do |m|
        _decode_bindings(m.body, m.name)
      end
    end

    def self._decode_bindings(bindings, method_name)
      bindings.each do |binding|
        _decode_value(binding.value, method_name, binding.name)
      end
    end
    private_class_method :_decode_bindings

    def self._decode_value(v, method_name, binding_name)
      case v.kind
      when "load_const"
        _decode_const_value(v, method_name, binding_name)

      when "assert", "update_prop"
        # The "value" field is a string reference
        unless v.raw_value.nil?
          unless v.raw_value.is_a?(String)
            raise ArgumentError,
                  "method #{method_name}: binding #{binding_name}: " \
                  "#{v.kind} value must be a string, got #{v.raw_value.class}"
          end
          v.value_ref = v.raw_value
        end

      when "if"
        _decode_bindings(v.then, method_name) if v.then
        _decode_bindings(v.else_, method_name) if v.else_

      when "loop"
        _decode_bindings(v.body, method_name) if v.body

      when "add_output"
        # satoshis and state_values decoded directly; nothing extra needed.
      end
    end
    private_class_method :_decode_value

    # True if +s+ is a JS-style decimal BigInt literal: optional leading
    # +-+, one or more ASCII digits, and a REQUIRED trailing +n+ marker.
    # Mirrors the discriminator used by compilers/go/ir/types.go and
    # compilers/python/runar_compiler/ir/types.py. The trailing +n+ is the
    # discriminator that separates a decimal-encoded BigInt from a hex-
    # encoded ByteString literal (which never carries the suffix), so a
    # hex string like "3030" is not mis-decoded as the integer 3030.
    def self.decimal_bigint_literal?(s)
      return false unless s.is_a?(String)
      return false if s.length < 2 || s[-1] != "n"

      start = s[0] == "-" ? 1 : 0
      body = s[start..-2]
      return false if body.empty?

      body.each_char.all? { |c| c >= "0" && c <= "9" }
    end

    def self._decode_const_value(v, method_name, binding_name)
      if v.raw_value.nil?
        raise ArgumentError,
              "method #{method_name}: binding #{binding_name}: load_const missing value"
      end

      raw = v.raw_value

      # Boolean -- must check before Integer because in Ruby true/false are not integers,
      # but we keep the same guard order as the Python port for clarity.
      if raw.is_a?(TrueClass) || raw.is_a?(FalseClass)
        v.const_bool = raw
        return
      end

      # String. Either a JS-style oversize BigInt literal ('123...n' with the
      # canonical 'n' suffix) or a hex-encoded ByteString literal. The 'n'
      # suffix is the discriminator -- without it the two cases are
      # indistinguishable when the literal is all-digit (e.g. '3030' is
      # both a valid decimal integer AND a valid hex bytestring).
      if raw.is_a?(String)
        if decimal_bigint_literal?(raw)
          int_val = raw[0..-2].to_i
          v.const_big_int = int_val
          v.const_int = int_val
          return
        end
        v.const_string = raw
        return
      end

      # Number (Integer or Float from JSON)
      if raw.is_a?(Integer) || raw.is_a?(Float)
        int_val = raw.to_i
        v.const_int = int_val
        v.const_big_int = int_val
        return
      end

      raise ArgumentError,
            "method #{method_name}: binding #{binding_name}: " \
            "unable to decode constant value: #{raw.inspect}"
    end
    private_class_method :_decode_const_value

    # -------------------------------------------------------------------
    # JSON deserialization helpers
    # -------------------------------------------------------------------

    def self._anf_value_from_hash(d)
      v = ANFValue.new(kind: d.fetch("kind", ""))

      v.name        = d["name"]
      v.raw_value   = d["value"]
      v.op          = d["op"]
      v.left        = d["left"]
      v.right       = d["right"]
      v.result_type = d["result_type"]
      v.operand     = d["operand"]
      v.func        = d["func"]
      v.args        = d["args"]
      v.object      = d["object"]
      v.method      = d["method"]
      v.cond        = d["cond"]
      v.count       = d["count"]
      v.iter_var    = d["iterVar"]
      # Loop start/step (#121). start is serialized as a JS-style "Nn" bigint
      # string; decode it to a Ruby Integer so stack lowering / the interpreter
      # can compute start + i*step. step is a plain integer (+1 / -1).
      v.start       = _decode_loop_start(d["start"]) if d.key?("start")
      v.step        = d["step"]
      v.preimage    = d["preimage"]
      # Issue #123: non-default sighash flag for a check_preimage node.
      v.sighash_flag = d["sighashFlag"]
      # Non-default Any-S binding variant ("all") for a check_preimage node.
      v.binding_variant = d["bindingVariant"]
      v.satoshis    = d["satoshis"]
      v.state_values = d["stateValues"]
      v.script_bytes = d["scriptBytes"]
      v.elements    = d["elements"]
      v.bytes       = d["bytes"]
      v.in_arity    = d["in_arity"]
      v.out_arity   = d["out_arity"]
      v.is_auto_injected_state_check = d["isAutoInjectedStateCheck"] == true

      # Nested bindings
      if d.key?("then") && !d["then"].nil?
        v.then = d["then"].map { |b| _anf_binding_from_hash(b) }
      end
      if d.key?("else") && !d["else"].nil?
        v.else_ = d["else"].map { |b| _anf_binding_from_hash(b) }
      end
      v.results = d["results"] if d.key?("results") && !d["results"].nil?
      if d.key?("body") && !d["body"].nil?
        v.body = d["body"].map { |b| _anf_binding_from_hash(b) }
      end

      v
    end
    private_class_method :_anf_value_from_hash

    # Decode a loop `start` field (#121). Accepts a JS-style "Nn" bigint
    # string (the canonical serialization), a plain JSON integer, or nil
    # (older payloads with no start → zero-start counting-up loop).
    def self._decode_loop_start(raw)
      return 0 if raw.nil?
      return raw if raw.is_a?(Integer)
      if raw.is_a?(String)
        return raw[0..-2].to_i if decimal_bigint_literal?(raw)
        return raw.to_i if raw.match?(/\A-?\d+\z/)
      end
      0
    end
    private_class_method :_decode_loop_start

    def self._anf_binding_from_hash(d)
      ANFBinding.new(
        name: d.fetch("name", ""),
        value: _anf_value_from_hash(d.fetch("value", {}))
      )
    end
    private_class_method :_anf_binding_from_hash

    def self._anf_param_from_hash(d)
      ANFParam.new(name: d.fetch("name", ""), type: d.fetch("type", ""))
    end
    private_class_method :_anf_param_from_hash

    def self._anf_property_from_hash(d)
      ANFProperty.new(
        name: d.fetch("name", ""),
        type: d.fetch("type", ""),
        readonly: d.fetch("readonly", false),
        initial_value: d["initialValue"]
      )
    end
    private_class_method :_anf_property_from_hash

    def self._anf_method_from_hash(d)
      ANFMethod.new(
        name: d.fetch("name", ""),
        params: d.fetch("params", []).map { |p| _anf_param_from_hash(p) },
        body: d.fetch("body", []).map { |b| _anf_binding_from_hash(b) },
        is_public: d.fetch("isPublic", false)
      )
    end
    private_class_method :_anf_method_from_hash

    # Build an +ANFProgram+ from a parsed JSON hash.
    def self.anf_program_from_hash(d)
      ANFProgram.new(
        contract_name: d.fetch("contractName", ""),
        properties: d.fetch("properties", []).map { |p| _anf_property_from_hash(p) },
        methods: d.fetch("methods", []).map { |m| _anf_method_from_hash(m) }
      )
    end

    # Deserialize an +ANFProgram+ from a JSON string.
    #
    # This does *not* decode constants or validate -- call
    # +decode_constants+ and the loader's +validate_ir+ separately.
    def self.anf_program_from_json(json_str)
      d = JSON.parse(json_str)
      anf_program_from_hash(d)
    end
  end
end
