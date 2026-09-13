# frozen_string_literal: true

# ANF IR loader and validator for the Runar compiler.
#
# Direct port of compilers/python/runar_compiler/ir/loader.py. Provides
# functions to load ANF IR from JSON (file path or string), validate the
# structure, and decode typed constant values.

require "json"
require "set"
require_relative "types"
# R-128 / R-165: the arity check below reads the frontend's own signature
# table rather than keeping a second copy of it.
require_relative "../frontend/typecheck"
require_relative "unknown_anf_kind_error"
require_relative "input_limits"

module RunarCompiler
  module IR
    # Maximum number of loop iterations allowed in a single loop binding.
    # Prevents resource exhaustion from malicious or accidental extremely large
    # loop counts during loop unrolling.
    MAX_LOOP_COUNT = 10_000

    # Set of all valid ANF value kinds.
    KNOWN_KINDS = Set.new(%w[
      load_param
      load_prop
      load_const
      bin_op
      unary_op
      call
      method_call
      if
      loop
      assert
      update_prop
      get_state_script
      check_preimage
      deserialize_state
      add_output
      add_raw_output
      add_data_output
      array_literal
      raw_script
    ]).freeze

    # Return true if +s+ contains only hex digits (0-9, a-f, A-F).
    # An empty string is considered valid hex.
    def self._hex_string?(s)
      s.match?(/\A[0-9a-fA-F]*\z/)
    end

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # Load an ANF IR program from a JSON string.
    #
    # Parses the JSON, decodes typed constant values, and validates the
    # structure. Raises +ArgumentError+ on any error.
    #
    # Rejects oversized (>MAX_IR_BYTES) or deeply-nested (>MAX_IR_NESTING)
    # payloads with the typed IR::InputLimits::IRSizeExceededError /
    # IR::InputLimits::IRNestingExceededError BEFORE JSON.parse runs.
    # BUG-008 follow-up.
    def self.load_ir(source)
      # DoS-bound guards run before JSON.parse so a malicious payload
      # cannot exhaust memory (size) or the Ruby fiber stack (nesting)
      # inside the deserializer.
      InputLimits.assert_ir_bytes_under_limit(source)
      InputLimits.assert_ir_nesting_under_limit(source)

      begin
        d = JSON.parse(source)
      rescue JSON::ParserError => e
        raise ArgumentError, "invalid IR JSON: #{e.message}"
      end

      program = anf_program_from_hash(d)

      # Decode typed constant values from raw JSON
      begin
        decode_constants(program)
      rescue ArgumentError => e
        raise ArgumentError, "decoding constants: #{e.message}"
      end

      errors = validate_ir(program)
      unless errors.empty?
        raise ArgumentError, "IR validation: #{errors[0]}"
      end

      program
    end

    # Load an ANF IR program from a JSON file on disk.
    #
    # Convenience wrapper around +load_ir+ that reads the file first.
    def self.load_ir_from_file(path)
      begin
        data = File.read(path, encoding: "utf-8")
      rescue SystemCallError => e
        raise ArgumentError, "reading IR file: #{e.message}"
      end

      load_ir(data)
    end

    # -------------------------------------------------------------------
    # Validation
    # -------------------------------------------------------------------

    # Validate the structure of a parsed ANF program.
    #
    # Returns an array of error strings (empty if valid).
    def self.validate_ir(program)
      errors = []

      if program.contract_name.nil? || program.contract_name.empty?
        errors << "contractName is required"
      end

      # R-126 / CL-BUG-164: an add_output must name exactly one state value per
      # MUTABLE property. Counted once, up front.
      mutable_count = program.properties.count { |p| !p.readonly }

      program.methods.each_with_index do |m, i|
        if m.name.nil? || m.name.empty?
          errors << "method[#{i}] has empty name"
        end

        m.params.each_with_index do |param, j|
          if param.name.nil? || param.name.empty?
            errors << "method #{m.name} param[#{j}] has empty name"
          end
          if param.type.nil? || param.type.empty?
            errors << "method #{m.name} param #{param.name} has empty type"
          end
        end

        errors.concat(_validate_bindings(m.body, m.name, mutable_count))
      end

      program.properties.each_with_index do |prop, i|
        if prop.name.nil? || prop.name.empty?
          errors << "property[#{i}] has empty name"
        end
        if prop.type.nil? || prop.type.empty?
          errors << "property #{prop.name} has empty type"
        end
      end

      # N-113 / R-081: a contract with no public method has no spending entry
      # point and emits an EMPTY locking script -- which is anyone-can-spend,
      # not merely useless. On the real @bsv/sdk `Spend` engine under full
      # consensus rules, an empty locking script with the one-byte push-only
      # witness OP_1 (0x51) validates. Before this guard the --ir path exited 0
      # and handed the SDKs a well-formed artifact whose "script" was "".
      #
      # The source pipeline already rejects the same shape in
      # frontend/validator.rb; validate_ir is reached only from the IR loader,
      # so this closes the rule's gap on externally supplied IR.
      #
      # Appended LAST so the structural diagnostics above keep priority -- a
      # malformed binding is the more actionable error when both are present
      # (load_ir raises errors[0]). Mirrors compilers/go/ir/loader.go,
      # including the ordering.
      unless program.methods.any?(&:is_public)
        errors << "contract #{program.contract_name} has no public methods " \
                  "— no spending entry points; an empty locking script is " \
                  "anyone-can-spend"
      end

      errors
    end

    # Validate a list of ANF bindings, including nested ones.
    # Allowed argument counts per builtin, READ from the frontend's own
    # signature table so the two cannot drift. Two builtins accept more than
    # one count (an optional trailing argument the table cannot express) and
    # one is variadic by a rule; both are special-cased in typecheck for the
    # same reasons. R-128 / R-165.
    VARIABLE_ARITY = {
      "assert" => [1, 2],
      "extractPrevOutputScript" => [2, 3]
    }.freeze

    def self._check_builtin_arity(method_name, binding)
      func_name = binding.value.func.to_s
      got = (binding.value.args || []).length

      if func_name == "merkleRootPoseidon2KB"
        # 8 leaf elements + 8 per proof level + index + depth.
        if got < 10
          return "method #{method_name} binding #{binding.name} calls " \
                 "#{func_name}() with #{got} argument(s); it takes at least 10 " \
                 "arguments (8 leaf + index + depth)"
        end
        if ((got - 10) % 8) != 0
          return "method #{method_name} binding #{binding.name} calls " \
                 "#{func_name}() with #{got} argument(s); it takes 8*depth + 10 arguments"
        end
        return nil
      end

      allowed = VARIABLE_ARITY[func_name]
      if allowed.nil?
        sig = ::RunarCompiler::Frontend::BUILTIN_FUNCTIONS[func_name]
        return nil if sig.nil?

        allowed = [sig.params.length]
      end
      return nil if allowed.include?(got)

      wanted = allowed.length == 1 ? allowed[0].to_s : "#{allowed[0..-2].join(', ')} or #{allowed[-1]}"
      "method #{method_name} binding #{binding.name} calls #{func_name}() with " \
        "#{got} argument(s); it takes #{wanted}"
    end

    def self._validate_bindings(bindings, method_name, mutable_count)
      errors = []

      bindings.each_with_index do |binding, i|
        if binding.name.nil? || binding.name.empty?
          errors << "method #{method_name} binding[#{i}] has empty name"
        end

        kind = binding.value.kind
        if kind.nil? || kind.empty?
          errors << "method #{method_name} binding #{binding.name} has empty kind"
          next
        end

        unless KNOWN_KINDS.include?(kind)
          errors << "method #{method_name} binding #{binding.name} " \
                    "has unknown kind #{kind.inspect}"
        end

        # R-128 / R-165: builtin call arity. The source pipeline type-checks
        # every call; `--ir` runs no frontend, so a wrong-arity call used to
        # reach stack lowering, where each dispatch family pops len(args) from
        # the stack MODEL and then emits a FIXED-arity opcode blob. `cat` with
        # one argument compiled to a bare OP_CAT; `assert` with none compiled
        # to an EMPTY script, dropping the contract's only guard.
        if kind == "call"
          err = _check_builtin_arity(method_name, binding)
          errors << err if err
        end

        # R-164 / CL-BUG-134: `super` outside a constructor.
        #
        # `super` emits no opcodes -- the constructor args are already on the
        # stack -- but stack lowering pushes a stackMap slot for it anyway:
        # +1 model, +0 physical. Invisible on the SOURCE path (the constructor
        # is never lowered to script) and reachable via `--ir`, where every
        # subsequent PICK/ROLL depth is off by one. Refusing beats inventing a
        # physical push for a call with no runtime meaning.
        if kind == "call" && binding.value.func == "super" && method_name != "constructor"
          errors << "super() is only valid in a constructor; method '#{method_name}' calls it. " \
                    "It emits no opcodes -- the constructor args are already on the stack -- so " \
                    "stack lowering pushes a model slot with no physical value, and every later " \
                    "PICK/ROLL depth in the method is off by one."
        end

        # R-126 / CL-BUG-164: add_output state-value arity.
        #
        # The source pipeline counts addOutput arity in the typechecker (the
        # N20 / N23 / N26 negatives). `--ir` runs no frontend, so such a node
        # reached stack lowering directly, and `_lower_add_output` serializes
        # the OP_RETURN payload with the MIN of the two lists. Under-arity
        # emitted an output carrying fewer state fields than the contract has;
        # over-arity silently dropped the surplus. Measured through each tier's
        # own --ir CLI on a two-mutable-field contract (correct arity = 1394
        # hexchars): go, rust, zig, ruby, python and java ALL accepted, emitting
        # 1388 and 1396 hexchars respectively.
        #
        # CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
        # mutable fields, so a short-payload continuation is spendable only by a
        # hand-crafted transaction, and the successor it produces is permanently
        # unspendable because the next call's deserialize_state slices at fixed
        # offsets. The message is shared verbatim with the other six tiers.
        if kind == "add_output"
          got = (binding.value.state_values || []).length
          if got != mutable_count
            errors << "add_output in method '#{method_name}' carries #{got} state " \
                      "values, but the contract declares #{mutable_count} mutable " \
                      "properties. The output's OP_RETURN payload is serialized from " \
                      "this list while deserialize_state slices the declared properties " \
                      "at fixed offsets, so any other count commits to a state payload " \
                      "no SDK-built transaction can produce and a successor that cannot " \
                      "be spent."
          end
        end

        # Validate nested bindings
        if kind == "if"
          if binding.value.then
            errors.concat(_validate_bindings(binding.value.then, method_name, mutable_count))
          end
          if binding.value.else_
            errors.concat(_validate_bindings(binding.value.else_, method_name, mutable_count))
          end
        end

        if kind == "loop"
          count = binding.value.count || 0
          if count < 0
            errors << "method #{method_name} binding #{binding.name} " \
                      "has negative loop count #{count}"
          end
          if count > MAX_LOOP_COUNT
            errors << "method #{method_name} binding #{binding.name} " \
                      "has loop count #{count} exceeding maximum #{MAX_LOOP_COUNT}"
          end
          if binding.value.body
            errors.concat(_validate_bindings(binding.value.body, method_name, mutable_count))
          end
        end

        if kind == "raw_script"
          body = binding.value.bytes || ""
          # N-113 / R-079: an empty span is a claim the emitter cannot honour.
          # Stack lowering models a raw_script purely from its declared arities
          # (it pops in_arity and pushes out_arity) because the bytes are
          # opaque to it, while emission writes nothing at all for a
          # zero-length span. The stack model and the script then disagree, and
          # every later PICK/ROLL depth derived from that model addresses the
          # wrong slot -- the span silently degrades to the identity function
          # and a different witness spends the output than the IR declared.
          #
          # The source path already rejects this ("asm() body must be a
          # non-empty hex string literal", frontend/validator.rb); --ir is the
          # same rule at the external-input trust boundary. All empty bodies
          # are rejected, including the degenerate in=0/out=0 case, because
          # mirroring the source validator exactly is worth more than an
          # arity-conditional rule that would differ from the rule one pass
          # earlier.
          if body.empty?
            errors << "method #{method_name} binding #{binding.name} " \
                      "raw_script has an empty bytes body but declares " \
                      "in_arity #{binding.value.in_arity || 0} / " \
                      "out_arity #{binding.value.out_arity || 0}; a span " \
                      "that emits no bytes cannot have a stack effect"
          end
          if body.length.odd?
            errors << "method #{method_name} binding #{binding.name} " \
                      "raw_script bytes have odd hex length #{body.length}"
          elsif !_hex_string?(body)
            errors << "method #{method_name} binding #{binding.name} " \
                      "raw_script bytes contain non-hex characters"
          end
          in_arity = binding.value.in_arity || 0
          if in_arity < 0
            errors << "method #{method_name} binding #{binding.name} " \
                      "raw_script has negative in_arity #{in_arity}"
          end
          out_arity = binding.value.out_arity || 0
          if out_arity < 0
            errors << "method #{method_name} binding #{binding.name} " \
                      "raw_script has negative out_arity #{out_arity}"
          end
        end
      end

      errors
    end
    private_class_method :_validate_bindings
  end
end
