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

    ANFProgram = Struct.new(:contract_name, :properties, :methods, keyword_init: true) do
      def initialize(contract_name: "", properties: [], methods: [])
        super(contract_name: contract_name, properties: properties, methods: methods)
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

    ANFMethod = Struct.new(:name, :params, :body, :is_public, keyword_init: true) do
      def initialize(name: "", params: [], body: [], is_public: false)
        super(name: name, params: params, body: body, is_public: is_public)
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
                    # -- loop ----------------------------------------------
                    :count,
                    :iter_var,
                    :body,
                    # -- assert, update_prop (value ref), check_preimage ---
                    :value_ref,
                    # -- check_preimage, deserialize_state -----------------
                    :preimage,
                    # -- add_output ----------------------------------------
                    :satoshis,
                    :state_values,
                    # -- add_raw_output ------------------------------------
                    :script_bytes,
                    # -- array_literal -------------------------------------
                    :elements

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
        @count = nil
        @iter_var = nil
        @body = nil
        @value_ref = nil
        @preimage = nil
        @satoshis = nil
        @state_values = nil
        @script_bytes = nil
        @elements = nil
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

      # String (hex-encoded bytes)
      if raw.is_a?(String)
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
      v.preimage    = d["preimage"]
      v.satoshis    = d["satoshis"]
      v.state_values = d["stateValues"]
      v.script_bytes = d["scriptBytes"]
      v.elements    = d["elements"]

      # Nested bindings
      if d.key?("then") && !d["then"].nil?
        v.then = d["then"].map { |b| _anf_binding_from_hash(b) }
      end
      if d.key?("else") && !d["else"].nil?
        v.else_ = d["else"].map { |b| _anf_binding_from_hash(b) }
      end
      if d.key?("body") && !d["body"].nil?
        v.body = d["body"].map { |b| _anf_binding_from_hash(b) }
      end

      v
    end
    private_class_method :_anf_value_from_hash

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
