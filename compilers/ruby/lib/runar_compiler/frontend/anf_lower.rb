# frozen_string_literal: true

# ANF lowering pass for the Runar compiler.
#
# Lowers a type-checked Runar AST to A-Normal Form IR.
# Direct port of compilers/python/runar_compiler/frontend/anf_lower.py.
#
# This is the most complex frontend pass. Every expression is recursively
# flattened into a sequence of let-bindings (ANFBinding) with fresh temp
# names (t0, t1, ...).

require "json"
require "set"
require_relative "../ir/types"
require_relative "ast_nodes"
require_relative "sighash_directive"

module RunarCompiler
  module Frontend
    # SIGHASH_ALL | SIGHASH_FORKID — the default @sighash mode (issue #123).
    # Byte-identical to the historically-pinned covenant binding blob.
    SIGHASH_DEFAULT = SighashDirective::SIGHASH_DEFAULT

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    # True for exactly the names LoweringContext#fresh_temp can mint.
    # @param name [String]
    # @return [Boolean]
    def self.temp_shaped?(name)
      name.length >= 2 && name[0] == "t" && name[1..].match?(/\A\d+\z/)
    end

    # Collect `t<digits>` variable-declaration names from a statement list.
    # @param stmts [Array]
    # @param out [Set]
    def self.collect_decl_names(stmts, out)
      stmts.each do |stmt|
        case stmt
        when VariableDeclStmt
          out << stmt.name if temp_shaped?(stmt.name)
        when IfStmt
          collect_decl_names(stmt.then || [], out)
          collect_decl_names(stmt.else_ || [], out)
        when ForStmt
          collect_decl_names([stmt.init, stmt.update].compact, out)
          collect_decl_names(stmt.body || [], out)
        end
      end
    end

    # Every `t<digits>` identifier the contract's own source binds, so
    # fresh_temp can never mint a name that shadows one.
    #
    # fresh_temp mints t0, t1, t2, ... while emit_named binds the developer's
    # own locals into the SAME binding namespace. Nothing reserved them against
    # each other, so a contract with a local named `t3` got a compiler temp
    # named `t3` written on top of it, and the reference that read the user's
    # value silently resolved to the compiler's.
    #
    # That deletes asserts. `const t3 = z - y; const t5 = y - t3;
    # assert(t5 === this.want)` lowered `t5 := load_prop want` over the user's
    # `t5`, leaving `assert(want === want)` -- always true, so the locking
    # script carried no guard and any witness could spend it. FAIL-OPEN, and
    # reachable with no branch involved.
    #
    # CONTRACT-wide, not method-wide, because private helpers are ANF-INLINED
    # into their callers: a helper local named `t3` is emit_named into the
    # CALLER's binding stream, so a per-method set would miss it.
    #
    # Only declarations and parameters are collected. An assignment target or a
    # ++/-- operand must name something already declared or a parameter, so
    # those are covered transitively. Only `t<digits>` names can ever collide,
    # so nothing else is reserved and temp numbering is unchanged for every
    # contract that does not already miscompile -- which is what leaves the
    # goldens and the cross-tier hex parity untouched. All seven tiers
    # implement this same rule.
    # @param contract [ContractNode]
    # @return [Set<String>]
    def self.collect_reserved_temps(contract)
      out = Set.new
      ([contract.constructor] + contract.methods).each do |m|
        m.params.each { |param| out << param.name if temp_shaped?(param.name) }
        collect_decl_names(m.body || [], out)
      end
      out
    end

    # Lower a type-checked Runar AST to ANF IR.
    #
    # Matches the TypeScript reference compiler's 04-anf-lower.ts exactly.
    #
    # @param contract [ContractNode]
    # @return [IR::ANFProgram]
    def self.lower_to_anf(contract)
      properties = _lower_properties(contract)
      methods = _lower_methods(contract)

      # Post-pass: lift update_prop from if-else branches into flat conditionals.
      # Mirrors the TS reference compiler's liftBranchUpdateProps (04-anf-lower.ts line 50).
      methods.each do |m|
        m.body = _lift_branch_update_props(m.body)
      end

      IR::ANFProgram.new(
        contract_name: contract.name,
        properties: properties,
        methods: methods,
        parent_class: contract.parent_class
      )
    end

    # -------------------------------------------------------------------
    # Byte-typed expression detection
    # -------------------------------------------------------------------

    BYTE_TYPES = %w[
      ByteString PubKey Sig Sha256 Ripemd160 Addr SigHashPreimage
      RabinSig RabinPubKey Point P256Point P384Point
    ].to_set.freeze
    private_constant :BYTE_TYPES

    BYTE_RETURNING_FUNCTIONS = %w[
      sha256 ripemd160 hash160 hash256 cat substr num2bin reverseBytes
      left right int2str toByteString pack ecAdd ecMul ecMulGen ecNegate
      ecMakePoint ecEncodeCompressed blake3Compress blake3Hash
      p256Add p256Mul p256MulGen p256Negate p256EncodeCompressed
      p384Add p384Mul p384MulGen p384Negate p384EncodeCompressed
    ].to_set.freeze
    private_constant :BYTE_RETURNING_FUNCTIONS

    # @param expr [Expression, nil]
    # @param ctx [LoweringContext]
    # @return [Boolean]
    def self._is_byte_typed_expr(expr, ctx)
      return false if expr.nil?

      return true if expr.is_a?(ByteStringLiteral)

      if expr.is_a?(Identifier)
        t = ctx.get_param_type(expr.name)
        return true if t && BYTE_TYPES.include?(t)
        t = ctx.get_property_type(expr.name)
        return true if t && BYTE_TYPES.include?(t)
        return true if ctx.local_byte_var?(expr.name)
        return false
      end

      if expr.is_a?(PropertyAccessExpr)
        t = ctx.get_property_type(expr.property)
        return true if t && BYTE_TYPES.include?(t)
        return false
      end

      if expr.is_a?(MemberExpr)
        if expr.object.is_a?(Identifier) && expr.object.name == "this"
          t = ctx.get_property_type(expr.property)
          return true if t && BYTE_TYPES.include?(t)
        end
        return false
      end

      if expr.is_a?(CallExpr)
        if expr.callee.is_a?(Identifier)
          # Expression-form asm<ByteString>({...}) yields a byte value.
          return expr.asm_return_type == "ByteString" if expr.callee.name == "asm"
          return true if BYTE_RETURNING_FUNCTIONS.include?(expr.callee.name)
          return true if expr.callee.name.length >= 7 && expr.callee.name[0, 7] == "extract"
        end
        return false
      end

      false
    end
    # Not private: called by LoweringContext methods

    # -------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------

    # Properties the constructor assigns a constructor PARAMETER to.
    #
    # These get their value from the deploy-time argument, so any initializer
    # on them is a default the argument overrides -- carrying it into
    # +initial_value+ would bake the default into the artifact and silently
    # discard the argument (NEW-001). The property must instead stay in the
    # constructor slot list so the SDK writes the argument.
    #
    # Deliberately narrow in three ways.
    #
    # 1. Only a BARE parameter reference counts. +this.a = 5n+ assigns a
    #    literal, not an argument, and keeps its initializer.
    # 2. The property<->parameter mapping must be ONE-TO-ONE. The artifact
    #    model is positional, so a parameter feeding two properties has no
    #    representation -- that shape is already undeployable today when
    #    written without initializers, and belongs to NEW-002.
    # 3. A property assigned more than once in the constructor is skipped, for
    #    the same reason.
    #
    # @param contract [ContractNode]
    # @return [Hash{String=>true}]
    def self._constructor_assigned_properties(contract)
      ctor = contract.constructor
      return {} if ctor.nil?

      params = ctor.params.map(&:name)
      prop_to_params = {}
      param_to_props = {}

      ctor.body.each do |stmt|
        next unless stmt.is_a?(AssignmentStmt)
        next unless stmt.target.is_a?(PropertyAccessExpr)

        prop = stmt.target.property
        value = stmt.value
        unless value.is_a?(Identifier) && params.include?(value.name)
          # Not a constructor argument: never strip this property.
          prop_to_params[prop] ||= []
          next
        end
        (prop_to_params[prop] ||= []) << value.name
        (param_to_props[value.name] ||= []) << prop
      end

      out = {}
      prop_to_params.each do |prop, ps|
        uniq = ps.uniq
        next unless uniq.length == 1
        next unless param_to_props[uniq.first].uniq.length == 1

        out[prop] = true
      end
      out
    end
    private_class_method :_constructor_assigned_properties

    # @param contract [ContractNode]
    # @return [Array<IR::ANFProperty>]
    def self._lower_properties(contract)
      ctor_assigned = _constructor_assigned_properties(contract)
      contract.properties.map do |prop|
        anf_prop = IR::ANFProperty.new(
          name: prop.name,
          type: _type_node_to_string(prop.type),
          readonly: prop.readonly
        )
        if !prop.initializer.nil? && !ctor_assigned[prop.name]
          anf_prop.initial_value = _extract_literal_value(prop.initializer)
          _check_state_bigint_magnitude(anf_prop)
        end
        # Propagate the FixedArray-expansion marker so the artifact assembler
        # can re-group the synthetic scalar run back into a logical FixedArray
        # state field.
        if prop.respond_to?(:synthetic_array_chain) && !prop.synthetic_array_chain.nil?
          anf_prop.synthetic_array_chain = prop.synthetic_array_chain
        end
        anf_prop
      end
    end
    private_class_method :_lower_properties

    # Magnitude a bigint state field gets: +num2bin-le8+ is a fixed 8-byte
    # little-endian SIGN-MAGNITUDE word, so bytes 0..6 plus the low 7 bits of
    # byte 7 carry the magnitude and 0x80 of byte 7 carries the sign.
    STATE_BIGINT_MAGNITUDE_LIMIT = 1 << 63

    # Reject a MUTABLE bigint property initialised beyond the 8-byte state word.
    #
    # The state section writes every bigint field with OP_NUM2BIN 8, which
    # cannot represent a magnitude of 2**63 or more. Nothing used to check: the
    # compiler stamped +encoding: "num2bin-le8"+ on the field and carried the
    # initializer verbatim, the SDK wrote the low 8 bytes of it into the
    # deployed state section, and the covenant then rebuilt the continuation
    # with its own OP_NUM2BIN 8 -- which produces different bytes -- so
    # hash256(outputs) never matched and the UTXO was permanently unspendable.
    # It deployed cleanly, with no diagnostic at compile time or deploy time.
    #
    # This catches the statically-known half. Values that only exist at call
    # time are stopped by the SDK serializer (packages/runar-rb/lib/runar/sdk/state.rb).
    #
    # READONLY properties are deliberately exempt: they are baked into the
    # locking script as script-number pushes, never into the state section, and
    # BSV script numbers are arbitrary-precision after Genesis.
    #
    # @param prop [IR::ANFProperty]
    # @return [void]
    def self._check_state_bigint_magnitude(prop)
      return if prop.readonly
      return unless ["bigint", "int"].include?(prop.type)

      value = prop.initial_value
      return unless value.is_a?(Integer)
      return if value.abs < STATE_BIGINT_MAGNITUDE_LIMIT

      raise ArgumentError,
            "Cannot compile state property '#{prop.name}' initialised to #{value}: " \
            "it does not fit the fixed 8-byte sign-magnitude state word (magnitude " \
            "must be < 2^63). Reduce the value, or make the property readonly if it " \
            "is a constant rather than state."
    end
    private_class_method :_check_state_bigint_magnitude

    # @param expr [Expression]
    # @return [String, Integer, Boolean, nil]
    def self._extract_literal_value(expr)
      return expr.value if expr.is_a?(BigIntLiteral)
      return expr.value if expr.is_a?(BoolLiteral)
      return expr.value if expr.is_a?(ByteStringLiteral)
      if expr.is_a?(UnaryExpr) && expr.op == "-"
        return -expr.operand.value if expr.operand.is_a?(BigIntLiteral)
      end
      nil
    end
    private_class_method :_extract_literal_value

    # -------------------------------------------------------------------
    # Methods
    # -------------------------------------------------------------------

    # @param contract [ContractNode]
    # @return [Array<IR::ANFMethod>]
    def self._lower_methods(contract)
      result = []

      # Lower constructor
      reserved_temps = collect_reserved_temps(contract)

      ctor_ctx = LoweringContext.new(contract)
      ctor_ctx.instance_variable_set(:@reserved_temps, reserved_temps)
      contract.constructor.params.each do |p|
        ctor_ctx.register_param_type(p.name, _type_node_to_string(p.type))
      end
      ctor_ctx.lower_statements(contract.constructor.body)
      result << IR::ANFMethod.new(
        name: "constructor",
        params: _lower_params(contract.constructor.params),
        body: ctor_ctx.bindings,
        is_public: false
      )

      # Issue #109: readonly fields carrying a +/** @embedAlways */+ directive
      # must survive DCE into the locking script. A readonly field no method
      # references lowers to no +load_prop+, so no constructor slot is emitted
      # and the field's deploy-time bytes vanish. Inject a +load_prop+ + a
      # +@ref:+ alias (the exact shape +const _bind = this.field;+ produces)
      # into the first public method's body — the alias keeps the +load_prop+
      # alive through dead-binding DCE, and stack lowering threads the pushed
      # value through and cleans it up at method end. One slot in the deployed
      # script suffices; every spending branch shares it.
      embed_fields = contract.properties.select { |p| p.readonly && _embed_always?(p) }
      embed_injected = false

      # Lower each method
      contract.methods.each do |method|
        method_ctx = LoweringContext.new(contract)
        method_ctx.instance_variable_set(:@reserved_temps, reserved_temps)

        # Issue #123: a non-default @sighash mode drives the OP_PUSH_TX binding
        # flag for any checkPreimage (auto-injected below, or a manual call) in
        # this method. Omitted for the default so the ANF (and pinned binding
        # blob) is unchanged.
        method_sighash = method.respond_to?(:sighash_type) ? method.sighash_type : nil
        if !method_sighash.nil? && method_sighash != SIGHASH_DEFAULT
          method_ctx.sighash_flag = method_sighash
        end

        # Register the developer-declared param types scoped to this method
        # before lowering its body, so byte-type analysis sees only this
        # method's params (issue #34).
        method.params.each do |p|
          method_ctx.register_param_type(p.name, _type_node_to_string(p.type))
        end

        # Register the declared param NAMES so a bare identifier resolves to
        # load_param before falling through to load_prop (#130). Without this,
        # a param whose name collides with a mutable state property lowered to
        # the stale deserialized property value instead of the witness param.
        # Explicit this.x is unaffected: PropertyAccessExpr lowering checks
        # property? before param? (below), so a stored property still wins.
        method.params.each do |p|
          method_ctx.add_param(p.name)
        end

        if contract.parent_class == "StatefulSmartContract" && method.visibility == "public"
          # Determine if this method verifies hashOutputs (needs change output support).
          # Methods that use addOutput / addDataOutput or mutate state need hashOutputs
          # verification.
          has_data_output = _method_has_add_data_output(method, contract)
          needs_change_output = (
            _method_mutates_state(method, contract) ||
            _method_has_add_output(method, contract) ||
            has_data_output
          )

          # Register implicit parameters
          if needs_change_output
            method_ctx.add_param("_changePKH")
            method_ctx.add_param("_changeAmount")
            method_ctx.register_param_type("_changePKH", "Ripemd160")
            method_ctx.register_param_type("_changeAmount", "bigint")
          end
          # Single-output continuation needs _newAmount to allow changing the UTXO satoshis.
          # Methods that emit only data outputs (no addOutput) still run the
          # single-output continuation path for their state continuation, so
          # they also need _newAmount.
          needs_new_amount = (_method_mutates_state(method, contract) || has_data_output) &&
                             !_method_has_add_output(method, contract)
          if needs_new_amount
            method_ctx.add_param("_newAmount")
            method_ctx.register_param_type("_newAmount", "bigint")
          end
          method_ctx.add_param("txPreimage")
          method_ctx.register_param_type("txPreimage", "SigHashPreimage")

          # Issue #123: the declared per-method sighash mode (default ALL|FORKID).
          # Drives BOTH the OP_PUSH_TX binding flag (so the derived sig re-computes
          # the tx sighash under this mode) AND the runtime preimage-type assert.
          sighash_mode = method_sighash.nil? ? SIGHASH_DEFAULT : method_sighash
          is_default_sighash = sighash_mode == SIGHASH_DEFAULT

          # Inject checkPreimage(txPreimage) at the start
          preimage_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
          check_result = method_ctx.emit(IR::ANFValue.new(kind: "check_preimage").tap do |v|
            v.preimage = preimage_ref
            # Omit for the default so the ANF (and pinned binding blob) is unchanged.
            v.sighash_flag = sighash_mode unless is_default_sighash
          end)
          method_ctx.emit(_make_assert(check_result))

          # GAP-302 / #123: pin the sighash type to the declared mode. The
          # auto-injected covenant verifies a real tx preimage, but without this
          # check the spend could use a DIFFERENT sighash flag than declared that
          # zeroes out preimage fields the contract (or its continuation) relies
          # on (hashOutputs / hashPrevouts / hashSequence). The value defaults to
          # 0x41 (SIGHASH_ALL|FORKID) so existing contracts emit byte-identical ANF.
          sig_hash_preimage_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
          sig_hash_type_ref = method_ctx.emit(_make_call("extractSigHashType", [sig_hash_preimage_ref]))
          expected_sig_hash_ref = method_ctx.emit(_make_load_const_int(sighash_mode))
          sig_hash_ok_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = "==="
            v.left = sig_hash_type_ref
            v.right = expected_sig_hash_ref
          end)
          method_ctx.emit(_make_assert(sig_hash_ok_ref))

          # Deserialize mutable state from the preimage's scriptCode
          has_state_prop = contract.properties.any? { |p| !p.readonly }
          if has_state_prop
            preimage_ref3 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
            method_ctx.emit(IR::ANFValue.new(kind: "deserialize_state").tap { |v| v.preimage = preimage_ref3 })
          end

          # Issue #109: preserve @embedAlways fields at the first user-statement
          # position (after the checkPreimage/deserialize preamble), mirroring
          # where a `const _bind = this.field;` idiom would sit.
          if !embed_injected && embed_fields.any?
            _emit_embed_always_preservation(method_ctx, embed_fields)
            embed_injected = true
          end

          # Lower the developer's method body
          method_ctx.lower_statements(method.body)

          # Determine state continuation type.
          #
          # === Continuation-hash construction ===
          #
          # Outputs are concatenated in the following order before hashing
          # with hash256:
          #   1. state outputs  (addOutput / addRawOutput, via addOutputRef)
          #   2. data outputs   (addDataOutput, via addDataOutputRef)
          #   3. change output  (P2PKH to _changePKH, value = _changeAmount)
          #
          # For the "single-output" fast path (no addOutput, but state mutates
          # or a data output is emitted), the state output is computed on the
          # fly from (preimage, stateScript, _newAmount); data outputs are
          # inserted BETWEEN the single state output and the change output.
          add_output_refs = method_ctx.get_add_output_refs
          add_data_output_refs = method_ctx.get_add_data_output_refs
          if add_output_refs.any? || add_data_output_refs.any? || _method_mutates_state(method, contract)
            # Build the P2PKH change output for hashOutputs verification
            #
            # #116: the SDK's buildCallTransaction OMITS the change output when
            # change <= 0 (an exact-cover call) and passes _changeAmount = 0.
            # Gate the change segment on _changeAmount != 0 at runtime so the
            # hashed output set matches the SDK at the exact-zero boundary -- the
            # segment is the P2PKH change output when non-zero, and empty bytes
            # (cat with empty is a no-op) when zero, reproducing the omission.
            # For any change > 0 the hashed bytes are unchanged; only the emitted
            # script gains the guard.
            change_pkh_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_changePKH" })
            change_amount_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_changeAmount" })
            zero_ref = method_ctx.emit(_make_load_const_int(0))
            change_nonzero_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
              v.op = "!=="
              v.left = change_amount_ref
              v.right = zero_ref
            end)
            change_then_ctx = method_ctx.sub_context
            change_then_ctx.emit(_make_call("buildChangeOutput", [change_pkh_ref, change_amount_ref]))
            method_ctx.sync_counter(change_then_ctx)
            change_else_ctx = method_ctx.sub_context
            change_else_ctx.emit(_make_load_const_string(""))
            method_ctx.sync_counter(change_else_ctx)
            change_output_ref = method_ctx.emit(IR::ANFValue.new(kind: "if").tap do |v|
              v.cond = change_nonzero_ref
              v.then = change_then_ctx.bindings
              v.else_ = change_else_ctx.bindings
            end)

            if add_output_refs.any?
              # Multi-output continuation: concat all state outputs, then all
              # data outputs, then change output, then hash.
              accumulated = add_output_refs[0]
              (1...add_output_refs.length).each do |i|
                accumulated = method_ctx.emit(_make_call("cat", [accumulated, add_output_refs[i]]))
              end
              add_data_output_refs.each do |data_ref|
                accumulated = method_ctx.emit(_make_call("cat", [accumulated, data_ref]))
              end
              accumulated = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
              hash_ref = method_ctx.emit(_make_call("hash256", [accumulated]))
              preimage_ref2 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref2]))
              eq_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "==="
                v.left = hash_ref
                v.right = output_hash_ref
                v.result_type = "bytes"
              end)
              method_ctx.emit(_make_auto_injected_state_check_assert(eq_ref))
            else
              # Single-output continuation: build raw output bytes, then
              # splice in any declared data outputs, then concat with
              # change, then hash.
              state_script_ref = method_ctx.emit(IR::ANFValue.new(kind: "get_state_script"))
              preimage_ref2 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              new_amount_ref = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_newAmount" })
              contract_output_ref = method_ctx.emit(_make_call("computeStateOutput", [preimage_ref2, state_script_ref, new_amount_ref]))
              accumulated = contract_output_ref
              add_data_output_refs.each do |data_ref|
                accumulated = method_ctx.emit(_make_call("cat", [accumulated, data_ref]))
              end
              all_outputs = method_ctx.emit(_make_call("cat", [accumulated, change_output_ref]))
              hash_ref = method_ctx.emit(_make_call("hash256", [all_outputs]))
              preimage_ref4 = method_ctx.emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
              output_hash_ref = method_ctx.emit(_make_call("extractOutputHash", [preimage_ref4]))
              eq_ref = method_ctx.emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "==="
                v.left = hash_ref
                v.right = output_hash_ref
                v.result_type = "bytes"
              end)
              method_ctx.emit(_make_auto_injected_state_check_assert(eq_ref))
            end
          end

          # Build augmented params list for ABI (filter out StatefulContext params)
          augmented_params = _lower_params(
            method.params.reject { |p| _is_stateful_context_param(p) }
          )
          if needs_change_output
            augmented_params << IR::ANFParam.new(name: "_changePKH", type: "Ripemd160")
            augmented_params << IR::ANFParam.new(name: "_changeAmount", type: "bigint")
          end
          if needs_new_amount
            augmented_params << IR::ANFParam.new(name: "_newAmount", type: "bigint")
          end
          augmented_params << IR::ANFParam.new(name: "txPreimage", type: "SigHashPreimage")

          # Intent sub-covenant intrinsic auto-injected witness params
          # (BSVM Phase 13). Appended AFTER txPreimage so unlocking scripts
          # push them adjacent to the preimage anchor. Mirrors Go ordering.
          method_ctx.method_scope.auto_injected_params.each do |p|
            augmented_params << p
          end

          result << IR::ANFMethod.new(
            name: method.name,
            params: augmented_params,
            body: method_ctx.bindings,
            is_public: true,
            sighash_type: method_sighash
          )
        else
          # Issue #109: stateless public methods (and stateless contracts'
          # spending entry points) are lowered here — inject @embedAlways
          # preservation into the first PUBLIC one before its body.
          if !embed_injected && embed_fields.any? && method.visibility == "public"
            _emit_embed_always_preservation(method_ctx, embed_fields)
            embed_injected = true
          end
          method_ctx.lower_statements(method.body)
          augmented = _lower_params(
            method.params.reject { |p| _is_stateful_context_param(p) }
          )
          # Private methods can also call the intent intrinsics; capture
          # their auto-injected witness params so a public method that
          # inlines this private picks them up via the shared methodScope.
          # The non-inlined ABI is still informative for callees.
          method_ctx.method_scope.auto_injected_params.each do |p|
            augmented << p
          end
          result << IR::ANFMethod.new(
            name: method.name,
            params: augmented,
            body: method_ctx.bindings,
            is_public: method.visibility == "public",
            sighash_type: method_sighash
          )
        end
      end

      result
    end
    private_class_method :_lower_methods

    # True when a property carries the +/** @embedAlways */+ directive (#109).
    # PropertyNode gained the +embed_always+ field with the directive; guard
    # +respond_to?+ so ANF lowering still works on AST nodes from formats /
    # code paths that predate the field.
    def self._embed_always?(prop)
      prop.respond_to?(:embed_always) && prop.embed_always == true
    end
    private_class_method :_embed_always?

    # Issue #109: emit the DCE-surviving preservation pair for each
    # +@embedAlways+ readonly field into the given (public) method context.
    #
    # Reproduces exactly what a hand-written +const _bind = this.field;+ lowers
    # to: a +load_prop+ followed by a +load_const("@ref:<t>")+ alias. The alias
    # marks the +load_prop+ as referenced (see collect_refs_from_value in
    # constant_fold.rb / dce.rb), so dead-binding DCE keeps it; stack lowering
    # then emits the field's constructor-slot placeholder and NIPs the unused
    # value off the stack at method end. The field's bytes therefore remain in
    # the deployed locking script for downstream recovery.
    def self._emit_embed_always_preservation(ctx, fields)
      fields.each do |field|
        load_ref = ctx.emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = field.name })
        ctx.emit_named("__embedAlways_#{field.name}", _make_load_const_string("@ref:#{load_ref}"))
      end
    end
    private_class_method :_emit_embed_always_preservation

    # Check if a parameter is a StatefulContext parameter (should be filtered from ANF).
    def self._is_stateful_context_param(param)
      param.type.is_a?(Frontend::CustomType) && param.type.name == "StatefulContext"
    end
    private_class_method :_is_stateful_context_param

    # @param params [Array<ParamNode>]
    # @return [Array<IR::ANFParam>]
    def self._lower_params(params)
      params.map do |p|
        IR::ANFParam.new(name: p.name, type: _type_node_to_string(p.type))
      end
    end
    private_class_method :_lower_params

    # -------------------------------------------------------------------
    # Lowering context
    # -------------------------------------------------------------------

    # Per-method bookkeeping shared between a LoweringContext and all its
    # sub-contexts (if/else branches, ternaries). The ABI-augmentation pass
    # in _lower_methods reads auto_injected_params after the method body is
    # lowered to append witness params to the final ABI. Mirrors the Go
    # reference compiler's methodScopeT struct.
    class MethodScope
      attr_reader :auto_injected_params
      attr_accessor :did_emit_hash_outputs_check

      def initialize
        @auto_injected_params = []
        @auto_injected_set = {}
        @did_emit_hash_outputs_check = false
      end

      # Idempotent: second call with the same name is a no-op.
      def record_auto_injected_param(name, type)
        return if @auto_injected_set[name]
        @auto_injected_set[name] = true
        @auto_injected_params << IR::ANFParam.new(name: name, type: type)
      end
    end

    # Manages temp variable generation and binding emission.
    #
    # Mirrors the Go lowerCtx struct exactly.
    class LoweringContext
      # @return [Array<IR::ANFBinding>]
      attr_reader :bindings

      # @return [IR::SourceLocation, nil]
      attr_accessor :current_source_loc

      def initialize(contract)
        @bindings = []
        @counter = 0
        @contract = contract
        @local_names = Set.new
        @param_names = Set.new
        # Method-scoped parameter types: name => type string. Populated once
        # per method/constructor before its body is lowered, and shared into
        # if/else sub-contexts. The byte-type analysis reads ONLY this hash so
        # a local in one method never matches a same-named param of a DIFFERENT
        # method. Mirrors the per-method scoping of the TS reference compiler.
        @param_types = {}
        @add_output_refs = []
        @add_data_output_refs = []
        @local_aliases = {}
        @local_byte_vars = Set.new
        @current_source_loc = nil
        # Param substitution stack used when inlining a private method's body
        # directly into this context. Mirrors TS / Go reference compilers'
        # paramAliasStack — see _inline_private_method_call below for usage.
        @param_alias_stack = {}
        # Intent sub-covenant intrinsic bookkeeping (BSVM Phase 13). Shared
        # with sub-contexts (if/else branches) so witness-param registrations
        # inside a branch surface at the parent method's ABI. Mirrors the
        # Go reference compiler's methodScopeT.
        @method_scope = MethodScope.new
        # Issue #123: non-default @sighash flag for this method (nil = default).
        @sighash_flag = nil
        # True in every context produced by +sub_context+ -- inside an if arm, a
        # loop body, or an inlined helper's block -- and false only in the
        # context a method's own body is lowered into.
        @nested = false
      end

      # @return [MethodScope] shared per-method bookkeeping for intent intrinsics
      attr_reader :method_scope

      # Issue #123: the declared non-default +@sighash+ flag for the method being
      # lowered, so a MANUAL +checkPreimage(pre)+ call binds under the same mode
      # as the method's declared sighash. nil = default ALL|FORKID.
      attr_accessor :sighash_flag

      # True in every context produced by +sub_context+. +_lift_branch_update_props+
      # walks method.body and does NOT recurse, so an +if+ its recogniser accepts
      # is only actually REWRITTEN at method top level.
      attr_accessor :nested

      # Push an alias for a parameter name, used while inlining the body of
      # a private method into this context: identifier references to that
      # param resolve to the caller's arg ref instead of emitting load_param.
      def push_param_alias(name, alias_ref)
        (@param_alias_stack[name] ||= []) << alias_ref
      end

      def pop_param_alias(name)
        stack = @param_alias_stack[name]
        return if stack.nil? || stack.empty?
        stack.pop
        @param_alias_stack.delete(name) if stack.empty?
      end

      def get_param_alias(name)
        stack = @param_alias_stack[name]
        return nil if stack.nil? || stack.empty?
        stack.last
      end

      # Look up a private method by name; returns the MethodNode or nil.
      def get_private_method(name)
        @contract.methods.find do |m|
          m.name == name && m.name != "constructor" && m.visibility != "public"
        end
      end

      # Whether a call to `name` should be ANF-inlined rather than emitted as
      # a method_call. True iff `name` is a private method that (transitively)
      # emits state outputs (addOutput / addRawOutput) or data outputs
      # (addDataOutput). Those refs MUST appear in the caller's binding stream
      # so they participate in the continuation hash; without ANF-level
      # inlining they would live in a sibling ANF method and the public
      # method's continuation hash would miss them.
      #
      # Mutation-only private helpers (no output intrinsics) are intentionally
      # NOT inlined — state mutation flows through state continuity.
      def should_inline_private?(name)
        m = get_private_method(name)
        return false if m.nil?
        RunarCompiler::Frontend.send(:_method_has_add_output, m, @contract) ||
          RunarCompiler::Frontend.send(:_method_has_add_data_output, m, @contract)
      end

      # Inline a private method's body directly into this context. Mirrors
      # TS/Go/Rust/Python reference compilers' inlinePrivateMethodCall.
      def inline_private_method_call(method_name, arg_refs)
        method = get_private_method(method_name)
        if method.nil?
          this_ref = emit(Frontend._make_load_const_string("@this"))
          return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
            v.object = this_ref
            v.method = method_name
            v.args = arg_refs
          end)
        end

        aliased_params = []
        n = [method.params.size, arg_refs.size].min
        n.times do |i|
          param_name = method.params[i].name
          push_param_alias(param_name, arg_refs[i])
          aliased_params << param_name
        end

        start_index = @bindings.size
        lower_statements(method.body)
        end_index = @bindings.size

        aliased_params.reverse_each { |p| pop_param_alias(p) }

        if end_index > start_index
          @bindings[end_index - 1].name
        else
          emit(Frontend._make_load_const_string("@void"))
        end
      end

      # Generate a fresh temp name that no user identifier can shadow.
      # @return [String]
      def fresh_temp
        name = "t#{@counter}"
        @counter += 1
        while @reserved_temps.include?(name)
          name = "t#{@counter}"
          @counter += 1
        end
        name
      end

      # Emit a binding and return its name.
      # @param value [IR::ANFValue]
      # @return [String]
      def emit(value)
        name = fresh_temp
        binding = IR::ANFBinding.new(name: name, value: value)
        binding.source_loc = @current_source_loc if @current_source_loc
        @bindings << binding
        name
      end

      # Emit a binding with a specific name.
      # @param name [String]
      # @param value [IR::ANFValue]
      def emit_named(name, value)
        binding = IR::ANFBinding.new(name: name, value: value)
        binding.source_loc = @current_source_loc if @current_source_loc
        @bindings << binding
      end

      # Register a local variable name.
      def add_local(name)
        @local_names.add(name)
      end

      # @return [Boolean]
      def local?(name)
        @local_names.include?(name)
      end

      # Register a parameter name.
      def add_param(name)
        @param_names.add(name)
      end

      # Register the type of a parameter scoped to the current method/constructor.
      # Read back by get_param_type for byte-type analysis.
      def register_param_type(name, type)
        @param_types[name] = type
      end

      # @return [Boolean]
      def param?(name)
        @param_names.include?(name)
      end

      # Set an alias for a local variable (used when if-statement branches
      # reassign the same local).
      def set_local_alias(local_name, binding_name)
        @local_aliases[local_name] = binding_name
      end

      # @return [String]
      def get_local_alias(local_name)
        @local_aliases.fetch(local_name, "")
      end

      # Track an add_output reference.
      def add_output_ref(ref)
        @add_output_refs << ref
      end

      # @return [Array<String>]
      def get_add_output_refs
        @add_output_refs
      end

      # Track an addDataOutput reference -- distinct from state outputs.
      # Data outputs are included in the continuation hash AFTER state
      # outputs and BEFORE the change output.
      def add_data_output_ref(ref)
        @add_data_output_refs << ref
      end

      # @return [Array<String>]
      def get_add_data_output_refs
        @add_data_output_refs
      end

      # Flatten addOutput args: if the second arg is an array literal,
      # expand its elements inline (e.g., [satoshis, [a, b, c]] -> [satoshis, a, b, c]).
      def _flatten_add_output_args(args)
        if args.length == 2 && args[1].is_a?(ArrayLiteralExpr)
          [args[0], *args[1].elements]
        else
          args
        end
      end

      # @return [Boolean]
      def property?(name)
        @contract.properties.any? { |p| p.name == name }
      end

      # Whether `name` is a private (non-public) method on the contract.
      # Used to route bare-identifier calls through the method_call inlining
      # path so Move's free-function helpers match TypeScript's `this.foo()`.
      # @return [Boolean]
      def _is_private_method(name)
        @contract.methods.any? do |m|
          m.name == name && m.name != "constructor" && m.visibility != "public"
        end
      end

      # Look up a parameter type by name. METHOD-SCOPED: only the current
      # method's (or constructor's) parameters are visible, so a local named
      # `x` in one method never matches a same-named param of a DIFFERENT
      # method. Populated via register_param_type before the body is lowered.
      # @return [String, nil]
      def get_param_type(name)
        @param_types[name]
      end

      # Look up a property type by name.
      # @return [String, nil]
      def get_property_type(name)
        @contract.properties.each do |p|
          return Frontend._type_node_to_string(p.type) if p.name == name
        end
        nil
      end

      # @return [Boolean]
      def local_byte_var?(name)
        @local_byte_vars.include?(name)
      end

      # Create a sub-context for nested blocks (if/else, loops).
      #
      # The counter continues from the parent. Local names and param names
      # are shared (copied).
      # @return [LoweringContext]
      def sub_context
        sub = LoweringContext.new(@contract)
        sub.instance_variable_set(:@counter, @counter)
        # Same contract, same namespace: an arm's temps must dodge the same
        # user identifiers the enclosing body does.
        sub.instance_variable_set(:@reserved_temps, @reserved_temps)
        sub.instance_variable_set(:@local_names, @local_names.dup)
        sub.instance_variable_set(:@param_names, @param_names.dup)
        sub.instance_variable_set(:@param_types, @param_types.dup)
        sub.instance_variable_set(:@local_aliases, @local_aliases.dup)
        sub.instance_variable_set(:@local_byte_vars, @local_byte_vars.dup)
        # Share the per-method intent-intrinsic bookkeeping so witness-param
        # registrations and the once-per-method hashOutputs flag propagate up
        # from if/else branches. Mirrors Go subContext.methodScope sharing.
        sub.instance_variable_set(:@method_scope, @method_scope)
        # Propagate the method's declared @sighash flag (issue #123) so a manual
        # checkPreimage inside an if/else branch binds under the same mode.
        sub.sighash_flag = @sighash_flag
        # _lift_branch_update_props walks method.body and does NOT recurse, so
        # an +if+ its recogniser accepts is only actually REWRITTEN at method
        # top level. lower_if_statement needs the same distinction before it
        # defers to that pass.
        sub.nested = true
        sub
      end

      # Sync the temp counter from a sub-context back to the parent.
      def sync_counter(sub)
        sub_counter = sub.instance_variable_get(:@counter)
        @counter = sub_counter if sub_counter > @counter
      end

      # -----------------------------------------------------------------
      # Statement lowering
      # -----------------------------------------------------------------

      # @param stmts [Array<Statement>]
      # Lower a statement block, threading down the set of identifiers the
      # enclosing blocks still read after this block ends. Only the
      # block-forming statements (if / for) consume it; see
      # +Frontend._reads_after_statement+.
      def lower_statements(stmts, reads_after_block = Set.new)
        stmts.each_with_index do |stmt, i|
          # Early-return nesting: when an if-statement's then-block ends with a
          # return and there is no else-branch, the remaining statements after the
          # if logically belong in the else-branch.
          if stmt.is_a?(IfStmt) &&
             (stmt.else_.nil? || stmt.else_.empty?) &&
             i + 1 < stmts.length &&
             Frontend._branch_ends_with_return(stmt.then)
            remaining = stmts[(i + 1)..]
            modified_if = IfStmt.new(
              condition: stmt.condition,
              then: stmt.then,
              else_: remaining
            )
            lower_statement(modified_if, reads_after_block)
            return
          end
          # Only the block-forming statements need to know what the code after
          # them still reads; computing it for every statement would be
          # quadratic for no benefit.
          reads_after =
            if stmt.is_a?(IfStmt) || stmt.is_a?(ForStmt)
              Frontend._reads_after_statement(stmts, i, reads_after_block)
            else
              Set.new
            end
          lower_statement(stmt, reads_after)
        end
      end

      # @param stmt [Statement]
      def lower_statement(stmt, reads_after = Set.new)
        # Propagate source location to emitted ANF bindings
        stmt_loc = stmt.respond_to?(:source_location) ? stmt.source_location : nil
        if stmt_loc
          @current_source_loc = IR::SourceLocation.new(
            file: stmt_loc.file,
            line: stmt_loc.line,
            column: stmt_loc.column
          )
        end

        case stmt
        when VariableDeclStmt
          _lower_variable_decl(stmt)
        when AssignmentStmt
          _lower_assignment(stmt)
        when IfStmt
          _lower_if_statement(stmt, reads_after)
        when ForStmt
          _lower_for_statement(stmt, reads_after)
        when ExpressionStmt
          lower_expr_to_ref(stmt.expr)
        when ReturnStmt
          if stmt.value
            ref = lower_expr_to_ref(stmt.value)
            # If the returned ref is not the name of the last emitted binding,
            # emit an explicit load so the return value is the last (top-of-stack)
            # binding.
            if @bindings.any? && @bindings.last.name != ref
              emit(Frontend._make_load_const_string("@ref:#{ref}"))
            end
          end
        end

        @current_source_loc = nil
      end

      # -----------------------------------------------------------------
      # Expression lowering (the core ANF conversion)
      # -----------------------------------------------------------------

      # @param expr [Expression, nil]
      # @return [String] the binding name
      def lower_expr_to_ref(expr)
        return emit(Frontend._make_load_const_int(0)) if expr.nil?

        case expr
        when BigIntLiteral
          emit(Frontend._make_load_const_int(expr.value))
        when BoolLiteral
          emit(Frontend._make_load_const_bool(expr.value))
        when ByteStringLiteral
          emit(Frontend._make_load_const_string(expr.value))
        when Identifier
          _lower_identifier(expr)
        when PropertyAccessExpr
          # Explicit this.x: a real contract property always wins, even when a
          # method param shares the name (#130). Now that declared params are
          # registered, the param? branch below must not shadow a stored property.
          if property?(expr.property)
            return emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = expr.property })
          end
          # this.txPreimage in StatefulSmartContract -> load_param (it's an
          # implicit injected param, not a stored property).
          if param?(expr.property)
            return emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = expr.property })
          end
          # this.x -> load_prop
          emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = expr.property })
        when MemberExpr
          _lower_member_expr(expr)
        when BinaryExpr
          # NEW-014: <tt>&&</tt> and <tt>||</tt> SHORT-CIRCUIT. They desugar to
          # the ternary, which stack lowering already emits as real OP_IF /
          # OP_ELSE control flow:
          #
          #     a && b   ==>   a ? b : false
          #     a || b   ==>   a ? true : b
          #
          # They used to lower to +bin_op+, i.e. OP_BOOLAND / OP_BOOLOR --
          # binary stack ops, so BOTH operands were pushed and therefore both
          # evaluated. +spec/semantics.md+ §3.7 licensed that with "This is
          # safe in Rúnar because all expressions are pure (no side effects
          # beyond +assert+)". Purity is not TOTALITY: the same document's §10
          # and §11.3 list division by zero as a runtime failure, and OP_SPLIT
          # / OP_NUM2BIN abort out of range. Evaluating the operand the source
          # skipped therefore aborted the script, and the ordinary defensive
          # guard --
          #
          #     assert(d === 0n || (100n / d) > 1n);
          #
          # -- compiled to a locking script the chain rejects for exactly the
          # input the guard exists to protect, while the AST interpreter (which
          # short-circuits, like every surface syntax the frontends accept)
          # reported success. §3.9 already specifies the ternary's untaken arm
          # as unevaluated, so laziness was already in the language;
          # <tt>&&</tt> / <tt>||</tt> were the sole eager outlier.
          #
          # Only SOURCE-level <tt>&&</tt> / <tt>||</tt> desugar here. The
          # compiler still synthesises +bin_op+ <tt>&&</tt> / <tt>||</tt>
          # internally to fold if/else-chain guard conditions; those operands
          # are already-bound refs to plain comparison results, so they cannot
          # abort and stay on the cheap opcodes.
          if %w[&& ||].include?(expr.op)
            is_or = expr.op == "||"
            constant = BoolLiteral.new(value: is_or)
            return _lower_ternary_expr(TernaryExpr.new(
                                         condition: expr.left,
                                         consequent: is_or ? constant : expr.right,
                                         alternate: is_or ? expr.right : constant
                                       ))
          end

          left_ref = lower_expr_to_ref(expr.left)
          right_ref = lower_expr_to_ref(expr.right)

          result_type = nil
          if %w[=== !==].include?(expr.op) &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end
          # For +, annotate byte-typed operands so stack lowering can emit OP_CAT.
          if expr.op == "+" &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end
          # For bitwise &, |, ^, annotate byte-typed operands.
          if %w[& | ^].include?(expr.op) &&
             (Frontend._is_byte_typed_expr(expr.left, self) || Frontend._is_byte_typed_expr(expr.right, self))
            result_type = "bytes"
          end

          emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = expr.op
            v.left = left_ref
            v.right = right_ref
            v.result_type = result_type
          end)
        when UnaryExpr
          operand_ref = lower_expr_to_ref(expr.operand)
          unary_val = IR::ANFValue.new(kind: "unary_op").tap do |v|
            v.op = expr.op
            v.operand = operand_ref
          end
          # For ~, annotate byte-typed operands so downstream passes know the result is bytes.
          if expr.op == "~" && Frontend._is_byte_typed_expr(expr.operand, self)
            unary_val.result_type = "bytes"
          end
          emit(unary_val)
        when CallExpr
          _lower_call_expr(expr)
        when TernaryExpr
          _lower_ternary_expr(expr)
        when IndexAccessExpr
          obj_ref = lower_expr_to_ref(expr.object)
          index_ref = lower_expr_to_ref(expr.index)
          emit(Frontend._make_call("__array_access", [obj_ref, index_ref]))
        when IncrementExpr
          _lower_increment_expr(expr)
        when DecrementExpr
          _lower_decrement_expr(expr)
        when ArrayLiteralExpr
          element_refs = expr.elements.map { |elem| lower_expr_to_ref(elem) }
          emit(IR::ANFValue.new(kind: "array_literal").tap { |v| v.elements = element_refs })
        else
          emit(Frontend._make_load_const_int(0))
        end
      end

      private

      # @param stmt [VariableDeclStmt]
      def _lower_variable_decl(stmt)
        value_ref = lower_expr_to_ref(stmt.init)
        add_local(stmt.name)
        if Frontend._is_byte_typed_expr(stmt.init, self)
          @local_byte_vars.add(stmt.name)
        end
        emit_named(stmt.name, Frontend._make_load_const_string("@ref:#{value_ref}"))
      end

      # @param stmt [AssignmentStmt]
      def _lower_assignment(stmt)
        value_ref = lower_expr_to_ref(stmt.value)

        # this.x = expr -> update_prop
        if stmt.target.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(stmt.target.property, value_ref))
          return
        end

        # local = expr -> re-bind
        if stmt.target.is_a?(Identifier)
          emit_named(stmt.target.name, Frontend._make_load_const_string("@ref:#{value_ref}"))
          return
        end

        # For other targets, lower the target expression
        lower_expr_to_ref(stmt.target)
      end

      # @param stmt [IfStmt]
      def _lower_if_statement(stmt, reads_after = Set.new)
        cond_ref = lower_expr_to_ref(stmt.condition)

        # Lower then-block into sub-context
        then_ctx = sub_context
        then_ctx.lower_statements(stmt.then, reads_after)
        sync_counter(then_ctx)

        # Lower else-block into sub-context
        else_ctx = sub_context
        if stmt.else_ && stmt.else_.any?
          else_ctx.lower_statements(stmt.else_, reads_after)
        end
        sync_counter(else_ctx)

        # 2026-04-30 audit finding F2: when a branch contains output
        # intrinsics, append a cat-chain inside each branch so the
        # branch's terminal value is the concat of its output bytes
        # (state then data, in declaration order). Balances runtime
        # stack effects across branches and lets the parent's
        # continuation hash see one ref per if representing the
        # chosen branch's full output set.
        branch_has_state_output =
          then_ctx.get_add_output_refs.any? ||
          else_ctx.get_add_output_refs.any?
        branch_has_outputs =
          branch_has_state_output ||
          then_ctx.get_add_data_output_refs.any? ||
          else_ctx.get_add_data_output_refs.any?

        then_output_bytes = ""
        else_output_bytes = ""
        if branch_has_outputs
          then_output_bytes = Frontend._append_branch_output_concat(then_ctx)
          else_output_bytes = Frontend._append_branch_output_concat(else_ctx)
        end

        # Branch-merged locals (2 or more). An +if+ expression carries exactly
        # ONE value, so the alias below can only rewire post-branch references
        # for a SINGLE merged local. With two or more -- or with the arms
        # reassigning DIFFERENT locals -- every later reference kept naming the
        # pre-branch binding, i.e. the dead initial value, and stack lowering
        # then registered one stack-map slot for N physical results and resolved
        # every later operand one slot off. Reported privately 2026-08-03; see
        # packages/runar-testing/src/__tests__/branch-merged-locals-vm.test.ts.
        #
        # Fix: give both arms the SAME result set in the SAME order by appending
        # an explicit rebind of every merged local to each arm.
        merged_locals = collect_branch_merged_locals(then_ctx, else_ctx)

        if branch_has_outputs
          reason = Frontend._branch_output_rejection_reason(
            then_ctx, else_ctx, then_output_bytes, else_output_bytes,
            merged_locals, reads_after
          )
          unless reason.nil?
            raise ArgumentError,
                  "Cannot compile conditional that both declares outputs and " \
                  "#{reason}. Move the addOutput/addRawOutput/addDataOutput " \
                  "call after the if-statement."
          end
        end

        # The +if+'s multi-result contract. Locals first, in the canonical
        # merge order both arms agree on, then the properties either arm
        # writes, in contract declaration order -- so all seven tiers derive
        # the same list from the same source. results[0] is the deepest slot.
        arm_props = []
        Frontend._collect_updated_props(then_ctx.bindings, arm_props)
        Frontend._collect_updated_props(else_ctx.bindings, arm_props)
        result_names = merged_locals.dup
        @contract.properties.each do |p|
          result_names << p.name if arm_props.include?(p.name)
        end

        # The result list is keyed by NAME everywhere downstream, so a local
        # that shares a contract property's name appears TWICE and both entries
        # take the PROPERTY path -- the local's value is silently replaced by
        # the property's, and the layout assertion cannot see it because both
        # slots are legitimately named the same. Refuse the exact collision
        # only; shadowing a property is otherwise fine.
        shadowed = merged_locals.find { |n| arm_props.include?(n) }
        if shadowed
          raise ArgumentError,
                "Local variable '#{shadowed}' shadows contract property " \
                "'this.#{shadowed}', and the conditional assigns both. The " \
                "branch's result slots are identified by name, so the two cannot " \
                "be told apart and the local's value would be silently replaced " \
                "by the property's. Rename the local."
        end

        # When to materialise the contract instead of leaving the arms to the
        # stack-lowerer's inference:
        #
        #   - two or more merged locals -- the pre-existing normalisation. Kept
        #     on exactly its old trigger so the four +__merge$+ goldens do not
        #     move.
        #   - any result at all when the ELSE arm carries code. This is the new
        #     case, and it is where every measured miscompile lives: one arm
        #     rebinds its local IN PLACE (net depth 0) while the other pushes a
        #     fresh slot (net +1), or an arm writes a property beside a rebound
        #     local, or the two arms write the same properties in a different
        #     order. The arms then leave different LAYOUTS, which no depth or
        #     liveness predicate can see.
        #
        # An +if+ WITHOUT an else keeps the preserve-the-old-value path in
        # lower_if (phase 3 copies each missing slot's same-named parent
        # value), which already produces exactly these results by construction
        # -- deliberately left intact. An arm that emits outputs is excluded:
        # its single value is the serialised output bytes, and
        # _branch_output_rejection_reason above already refuses every
        # combination that would need a second result.
        #
        # EXCLUDED: an +if+ that _lift_branch_update_props will rewrite. That
        # pass (deep-review finding C20) turns a conditional-property-assignment
        # chain into one flat single-valued +if+ per property plus a top-level
        # +update_prop+, so the surviving +if+s carry no property result and
        # need no declaration. Appending the normalisation block first would
        # ALSO silently disable that pass: its recogniser requires the arm's
        # last binding to be the +update_prop+ with everything before it
        # side-effect free, and the block adds a second +update_prop+ behind it.
        # TicTacToe's position dispatch is exactly that shape, and losing the
        # lift there produced an unspendable +move+ script.
        #
        # The exclusion must be exactly "the lift WILL rewrite this +if+", which
        # is narrower than "the lift's recogniser accepts it" in TWO ways -- both
        # were live defects producing an unspendable UTXO: the lift only rewrites
        # chains of TWO OR MORE branches (_collect_update_branches returns a
        # ONE-element list for the assert-false-else guard), and it only walks
        # method.body, passing loop bodies and surviving arms through untouched,
        # while declares_results is evaluated at EVERY nesting depth.
        #
        # A chain's DEEPEST +if+ is never at top level, so it now declares
        # results and carries a normalisation block -- which is why
        # _collect_update_branches strips a declared block before matching
        # (_strip_declared_results).
        lifted = Frontend.send(:_collect_update_branches,
                               cond_ref, then_ctx.bindings, else_ctx.bindings)
        will_be_lifted = !nested && !lifted.nil? && lifted.length >= 2
        declares_results = !branch_has_outputs && !will_be_lifted &&
                           (merged_locals.length >= 2 ||
                            (!result_names.empty? && else_ctx.bindings.any?))

        if declares_results
          Frontend._append_branch_results(then_ctx, result_names, arm_props)
          sync_counter(then_ctx)
          Frontend._append_branch_results(else_ctx, result_names, arm_props)
          sync_counter(else_ctx)
        end

        if_name = emit(IR::ANFValue.new(kind: "if").tap do |v|
          v.cond = cond_ref
          v.then = then_ctx.bindings
          v.else_ = else_ctx.bindings
          v.results = result_names.dup if declares_results
        end)

        if branch_has_outputs
          # Register the if's value once with the parent's continuation
          # tracker. CRITICAL: pick the right tracker. If either
          # branch produces a STATE output, the parent must take the
          # multi-output continuation path, so we register as a state
          # output ref. If neither branch produces a state output and
          # at least one branch produces a data output, we register
          # as a DATA output ref so the parent keeps its single-output
          # `computeStateOutput` continuation and the data-output
          # bytes splice in BETWEEN the state output and the change
          # output. Without this, a branch with only `addDataOutput`
          # was incorrectly forced onto the multi-output path,
          # dropping the canonical state continuation.
          if branch_has_state_output
            add_output_ref(if_name)
          else
            add_data_output_ref(if_name)
          end
        end

        # If both branches end by reassigning the same SINGLE local variable,
        # alias that variable to the if-expression result.
        #
        # Skipped when the arms were normalised above: there the +if+ DECLARES
        # its results, and each one keeps its OWN name through the reconcile in
        # the stack lowerer.
        if !declares_results && then_ctx.bindings.any? && else_ctx.bindings.any?
          then_last = then_ctx.bindings.last
          else_last = else_ctx.bindings.last
          if then_last.name == else_last.name && local?(then_last.name)
            set_local_alias(then_last.name, if_name)
          end
        end
      end

      # The locals from the enclosing scope that either arm of an if-statement
      # reassigns, in a canonical order both arms can agree on: the then-arm's
      # reassignments in order of last rebind, then the else-only ones in the
      # same order.
      #
      # Only names the PARENT already knows as locals count -- +sub_context+
      # copies the local-name set by value, so a local declared inside a branch
      # never reaches the parent's set and is correctly excluded (it is not live
      # after the if).
      def collect_branch_merged_locals(then_ctx, else_ctx)
        last_rebind_order = lambda do |branch|
          last_index = {}
          branch.bindings.each_with_index do |b, i|
            last_index[b.name] = i if local?(b.name)
          end
          last_index.sort_by { |_, i| i }.map(&:first)
        end
        merged = last_rebind_order.call(then_ctx)
        last_rebind_order.call(else_ctx).each do |name|
          merged << name unless merged.include?(name)
        end
        merged
      end

      # @param stmt [ForStmt]
      def _lower_for_statement(stmt, reads_after = Set.new)
        # Resolve the loop's compile-time shape: start value, step direction,
        # and iteration count. Non-zero starts and countdown loops are
        # supported (#121) — on iteration i the iterator holds start + i*step.
        shape = Frontend._extract_loop_shape(stmt)

        # Lower body into sub-context. The body repeats, so every read anywhere
        # in it is a read that happens after any given statement inside it.
        body_reads = reads_after.dup
        stmt.body.each { |s| Frontend._collect_statement_reads(s, body_reads) }

        body_ctx = sub_context
        body_ctx.lower_statements(stmt.body, body_reads)
        sync_counter(body_ctx)

        emit(IR::ANFValue.new(kind: "loop").tap do |v|
          v.count = shape[:count]
          v.body = body_ctx.bindings
          v.iter_var = stmt.init ? stmt.init.name : ""
          v.start = shape[:start]
          v.step = shape[:step]
        end)
      end

      # @param id_node [Identifier]
      # @return [String]
      def _lower_identifier(id_node)
        name = id_node.name

        # 'this' is not a value in ANF
        return emit(Frontend._make_load_const_string("@this")) if name == "this"

        # Param alias takes precedence over normal param lookup. Set when a
        # private method's body is being inlined into this context — the
        # private's param names map to the caller's arg refs.
        param_alias = get_param_alias(name)
        return param_alias unless param_alias.nil?

        # Check if it's a registered parameter (e.g. txPreimage)
        return emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = name }) if param?(name)

        # Check if it's a local variable -- reference it directly
        # (or use its alias if reassigned by an if-statement)
        if local?(name)
          a = get_local_alias(name)
          return a unless a.empty?
          return name
        end

        # Check if it's a contract property
        return emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = name }) if property?(name)

        # Default: treat as parameter (this is how params get loaded lazily)
        emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = name })
      end

      # @param e [MemberExpr]
      # @return [String]
      def _lower_member_expr(e)
        # this.x -> load_prop
        if e.object.is_a?(Identifier) && e.object.name == "this"
          return emit(IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = e.property })
        end

        # SigHash.ALL etc. -> load constant
        if e.object.is_a?(Identifier) && e.object.name == "SigHash"
          sig_hash_values = {
            "ALL"          => 0x01,
            "NONE"         => 0x02,
            "SINGLE"       => 0x03,
            "FORKID"       => 0x40,
            "ANYONECANPAY" => 0x80
          }.freeze
          val = sig_hash_values[e.property]
          return emit(Frontend._make_load_const_int(val)) unless val.nil?
        end

        # General member access
        obj_ref = lower_expr_to_ref(e.object)
        emit(IR::ANFValue.new(kind: "method_call").tap do |v|
          v.object = obj_ref
          v.method = e.property
        end)
      end

      # @param e [CallExpr]
      # @return [String]
      def _lower_call_expr(e)
        callee = e.callee

        # super(...) call -- accepts both Identifier("super") and MemberExpr(super, "")
        is_super = (callee.is_a?(Identifier) && callee.name == "super") ||
                   (callee.is_a?(MemberExpr) && callee.object.is_a?(Identifier) && callee.object.name == "super")
        if is_super
          arg_refs = _lower_args(e.args)
          return emit(Frontend._make_call("super", arg_refs))
        end

        # assert(expr)
        if callee.is_a?(Identifier) && callee.name == "assert"
          if e.args.length >= 1
            value_ref = lower_expr_to_ref(e.args[0])
            return emit(Frontend._make_assert(value_ref))
          end
          false_ref = emit(Frontend._make_load_const_bool(false))
          return emit(Frontend._make_assert(false_ref))
        end

        # checkPreimage(preimage)
        if callee.is_a?(Identifier) && callee.name == "checkPreimage"
          if e.args.length >= 1
            preimage_ref = lower_expr_to_ref(e.args[0])
            return emit(IR::ANFValue.new(kind: "check_preimage").tap do |v|
              v.preimage = preimage_ref
              # Issue #123: honour the method's declared @sighash on manual calls.
              v.sighash_flag = @sighash_flag unless @sighash_flag.nil?
            end)
          end
        end

        # ---- Intent sub-covenant intrinsics (BSVM Phase 13) -------------
        # See docs/cross-covenant-pattern.md. All three are pure frontend
        # sugar that desugars to existing ANF primitives + auto-injected
        # method params; no new ANF kinds, no Stack-IR codegen changes.

        # extractPrevOutputScript(inputIndex_literal, expectedScriptHash) -> ByteString
        # extractPrevOutputScript(inputIndex_literal, expectedScriptPrefixHash, prefixLen_literal) -> ByteString
        #
        # Witness-bridge sugar. Auto-injects a hidden method parameter named
        # `_prevOutScript_<inputIndex>` (one per distinct index in the method
        # body), emits a hash assertion, and returns the witness ref for
        # caller substring extraction.
        #
        # 2-arg form: hash256(witness) === expectedScriptHash. Pins the full
        #   prev-output script byte-for-byte.
        # 3-arg form: hash256(substr(witness, 0, prefixLen)) ===
        #   expectedScriptPrefixHash. Pins the policy prefix only, leaving the
        #   pushdata tail free to vary. Required for the intent-template
        #   matching use case where each successor intent UTXO has a unique
        #   tail (BSVM Mode 3 permissionless step-in, Crit-2).
        if callee.is_a?(Identifier) && callee.name == "extractPrevOutputScript"
          if e.args.length != 2 && e.args.length != 3
            return emit(Frontend._make_load_const_string(""))
          end
          idx_lit = e.args[0]
          unless idx_lit.is_a?(BigIntLiteral) && !idx_lit.value.nil?
            return emit(Frontend._make_load_const_string(""))
          end
          idx = idx_lit.value.to_i
          param_name = "_prevOutScript_#{idx}"
          @method_scope.record_auto_injected_param(param_name, "ByteString")
          add_param(param_name)
          register_param_type(param_name, "ByteString")
          witness_ref = emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = param_name })
          expected_hash_ref = lower_expr_to_ref(e.args[1])

          # Determine which bytes to hash: full witness (2-arg) or prefix
          # (3-arg). The substr happens at script-execution time; the literal
          # prefixLen is baked into the emitted Stack-IR.
          if e.args.length == 3
            prefix_len_lit = e.args[2]
            unless prefix_len_lit.is_a?(BigIntLiteral) && !prefix_len_lit.value.nil?
              return emit(Frontend._make_load_const_string(""))
            end
            zero_ref = emit(Frontend._make_load_const_int(0))
            prefix_len_ref = emit(Frontend._make_load_const_int(prefix_len_lit.value.to_i))
            bytes_to_hash_ref = emit(Frontend._make_call("substr", [witness_ref, zero_ref, prefix_len_ref]))
          else
            bytes_to_hash_ref = witness_ref
          end

          actual_hash_ref = emit(Frontend._make_call("hash256", [bytes_to_hash_ref]))
          eq_ref = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = "==="
            v.left = actual_hash_ref
            v.right = expected_hash_ref
            v.result_type = "bytes"
          end)
          emit(Frontend._make_assert(eq_ref))
          return witness_ref
        end

        # requireOutputP2PKH(outputIndex_literal, pubkeyHash, amount) -> void.
        # Asserts that the tx's output at outputIndex is a standard P2PKH
        # paying `amount` satoshis to `pubkeyHash`. Auto-injects
        # `_serialisedOutputs` (once per method) and emits
        # hash256(serialisedOutputs) == extractOutputHash(txPreimage) the
        # first time the intrinsic is called in a method body. Subsequent
        # calls in the same method skip the hashOutputs check and emit only
        # the per-output substring assertion.
        #
        # v1 assumes all outputs in the serialised set are exactly 34 bytes
        # (8-byte LE amount ‖ 0x19 length ‖ 25-byte P2PKH script). Byte
        # offset of output i is i*34.
        if callee.is_a?(Identifier) && callee.name == "requireOutputP2PKH"
          return emit(Frontend._make_load_const_string("")) if e.args.length != 3
          idx_lit = e.args[0]
          unless idx_lit.is_a?(BigIntLiteral) && !idx_lit.value.nil?
            return emit(Frontend._make_load_const_string(""))
          end
          idx = idx_lit.value.to_i

          @method_scope.record_auto_injected_param("_serialisedOutputs", "ByteString")
          add_param("_serialisedOutputs")
          register_param_type("_serialisedOutputs", "ByteString")

          # Emit the hashOutputs(preimage) check exactly once per method.
          unless @method_scope.did_emit_hash_outputs_check
            @method_scope.did_emit_hash_outputs_check = true
            serialised_ref = emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_serialisedOutputs" })
            actual_out_hash_ref = emit(Frontend._make_call("hash256", [serialised_ref]))
            preimage_ref = emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
            expected_out_hash_ref = emit(Frontend._make_call("extractOutputHash", [preimage_ref]))
            hash_eq_ref = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
              v.op = "==="
              v.left = actual_out_hash_ref
              v.right = expected_out_hash_ref
              v.result_type = "bytes"
            end)
            emit(Frontend._make_assert(hash_eq_ref))
          end

          # Lower the user-supplied args (pubkeyHash, amount).
          pubkey_hash_ref = lower_expr_to_ref(e.args[1])
          amount_ref = lower_expr_to_ref(e.args[2])

          # Construct expected P2PKH output bytes:
          #   <amount: 8-byte LE> ‖ 0x19 0x76 0xa9 0x14 ‖ <pubkeyHash: 20 bytes> ‖ 0x88 0xac
          eight_ref = emit(Frontend._make_load_const_int(8))
          amount_bytes_ref = emit(Frontend._make_call("num2bin", [amount_ref, eight_ref]))
          # 0x19 0x76 0xa9 0x14 — script length byte + OP_DUP OP_HASH160 OP_PUSH20
          prefix_ref = emit(Frontend._make_load_const_string("1976a914"))
          # 0x88 0xac — OP_EQUALVERIFY OP_CHECKSIG
          suffix_ref = emit(Frontend._make_load_const_string("88ac"))
          cat1_ref = emit(Frontend._make_call("cat", [amount_bytes_ref, prefix_ref]))
          cat2_ref = emit(Frontend._make_call("cat", [cat1_ref, pubkey_hash_ref]))
          expected_output_ref = emit(Frontend._make_call("cat", [cat2_ref, suffix_ref]))

          # Substring extract at idx*34 length 34, assert equal.
          serialised_ref2 = emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "_serialisedOutputs" })
          offset_ref = emit(Frontend._make_load_const_int(idx * 34))
          length_ref = emit(Frontend._make_load_const_int(34))
          extracted_ref = emit(Frontend._make_call("substr", [serialised_ref2, offset_ref, length_ref]))
          out_eq_ref = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = "==="
            v.left = extracted_ref
            v.right = expected_output_ref
            v.result_type = "bytes"
          end)
          return emit(Frontend._make_assert(out_eq_ref))
        end

        # currentBlockHeight() -> bigint. Pure source-level desugar to
        # extractLocktime(this.txPreimage). Only valid in StatefulSmartContract
        # methods (typecheck enforces).
        if callee.is_a?(Identifier) && callee.name == "currentBlockHeight"
          preimage_ref = emit(IR::ANFValue.new(kind: "load_param").tap { |v| v.name = "txPreimage" })
          return emit(Frontend._make_call("extractLocktime", [preimage_ref]))
        end

        # this.addOutput(satoshis, val1, val2, ...) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addOutput"
          flattened = _flatten_add_output_args(e.args)
          arg_refs = _lower_args(flattened)
          satoshis = arg_refs[0]
          state_values = arg_refs[1..]
          ref = emit(IR::ANFValue.new(kind: "add_output").tap do |v|
            v.satoshis = satoshis
            v.state_values = state_values
            v.preimage = ""
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addRawOutput(satoshis, scriptBytes) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addRawOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_raw_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addDataOutput(satoshis, scriptBytes) via PropertyAccessExpr. Like
        # addRawOutput in wire shape, but included in the continuation hash
        # AFTER state outputs and BEFORE the change output.
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addDataOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_data_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_data_output_ref(ref)
          return ref
        end

        # this.addOutput(satoshis, val1, val2, ...) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addOutput"
          flattened = _flatten_add_output_args(e.args)
          arg_refs = _lower_args(flattened)
          satoshis = arg_refs[0]
          state_values = arg_refs[1..]
          ref = emit(IR::ANFValue.new(kind: "add_output").tap do |v|
            v.satoshis = satoshis
            v.state_values = state_values
            v.preimage = ""
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addRawOutput(satoshis, scriptBytes) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addRawOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_raw_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_output_ref(ref)
          return ref
        end

        # this.addDataOutput(satoshis, scriptBytes) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addDataOutput"
          arg_refs = _lower_args(e.args)
          satoshis = arg_refs[0]
          script_bytes_ref = arg_refs[1]
          ref = emit(IR::ANFValue.new(kind: "add_data_output").tap do |v|
            v.satoshis = satoshis
            v.script_bytes = script_bytes_ref
          end)
          add_data_output_ref(ref)
          return ref
        end

        # this.getStateScript() via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr) && callee.property == "getStateScript"
          return emit(IR::ANFValue.new(kind: "get_state_script"))
        end

        # this.getStateScript() via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "getStateScript"
          return emit(IR::ANFValue.new(kind: "get_state_script"))
        end

        # this.method(...) via PropertyAccessExpr
        if callee.is_a?(PropertyAccessExpr)
          arg_refs = _lower_args(e.args)
          if should_inline_private?(callee.property)
            return inline_private_method_call(callee.property, arg_refs)
          end
          this_ref = emit(Frontend._make_load_const_string("@this"))
          return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
            v.object = this_ref
            v.method = callee.property
            v.args = arg_refs
          end)
        end

        # this.method(...) via MemberExpr
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this"
          arg_refs = _lower_args(e.args)
          if should_inline_private?(callee.property)
            return inline_private_method_call(callee.property, arg_refs)
          end
          this_ref = emit(Frontend._make_load_const_string("@this"))
          return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
            v.object = this_ref
            v.method = callee.property
            v.args = arg_refs
          end)
        end

        # asm({...}) compiler intrinsic -- the parser has already normalised
        # the object-literal argument into three positional args
        # (body, in_arity, out_arity). Lower it to a single opaque raw_script
        # ANF binding; the hex body passes through unchanged. Diagnostics for
        # malformed args were already pushed by the validator -- here we
        # defensively coerce missing values to safe defaults.
        if callee.is_a?(Identifier) && callee.name == "asm"
          bytes = ""
          in_arity = 0
          out_arity = 1
          if e.args.length >= 1 && e.args[0].is_a?(ByteStringLiteral)
            bytes = e.args[0].value
          end
          if e.args.length >= 2 && e.args[1].is_a?(BigIntLiteral)
            in_arity = e.args[1].value.to_i
          end
          if e.args.length >= 3 && e.args[2].is_a?(BigIntLiteral)
            out_arity = e.args[2].value.to_i
          end
          return emit(IR::ANFValue.new(kind: "raw_script").tap do |v|
            v.bytes = bytes
            v.in_arity = in_arity
            v.out_arity = out_arity
          end)
        end

        # Direct function call: sha256(x), checkSig(sig, pk), etc.
        if callee.is_a?(Identifier)
          arg_refs = _lower_args(e.args)
          # Bare identifier calls that match a private method on the contract
          # (e.g. Move's `require_owner(contract, sig)` which the parser strips
          # to `requireOwner(sig)`) must be routed through the same inlining
          # path as `this.requireOwner(sig)` so downstream stack lowering can
          # inline the body. Keeps .runar.move in sync with .runar.ts.
          if _is_private_method(callee.name)
            if should_inline_private?(callee.name)
              return inline_private_method_call(callee.name, arg_refs)
            end
            this_ref = emit(Frontend._make_load_const_string("@this"))
            return emit(IR::ANFValue.new(kind: "method_call").tap do |v|
              v.object = this_ref
              v.method = callee.name
              v.args = arg_refs
            end)
          end
          return emit(Frontend._make_call(callee.name, arg_refs))
        end

        # General call
        callee_ref = lower_expr_to_ref(callee)
        arg_refs = _lower_args(e.args)
        emit(IR::ANFValue.new(kind: "method_call").tap do |v|
          v.object = callee_ref
          v.method = "call"
          v.args = arg_refs
        end)
      end

      # @param args [Array<Expression>]
      # @return [Array<String>]
      def _lower_args(args)
        args.map { |arg| lower_expr_to_ref(arg) }
      end

      # @param e [TernaryExpr]
      # @return [String]
      # Lower one arm of a ternary so the arm ENDS with its result binding.
      #
      # NEW-016: +lower_expr_to_ref+ returns an existing ref without emitting
      # anything when the arm is a bare identifier -- <tt>g ? f : c === 0n</tt>
      # produced <tt>then: []</tt>, an +if+ arm with no bindings at all. Stack
      # lowering reads an arm's result off its stack effect, so a +0 arm has no
      # result to adopt and the depth reconcile padded the shortfall with an
      # EMPTY push. The contract compiled clean, the AST interpreter accepted
      # it, and the real engine rejected the spend with "OP_VERIFY requires the
      # top stack value to be truthy" over a stack of <tt>[01, ]</tt> -- the
      # arm's +true+ replaced by an empty (false) value. An ordinary contract
      # deployed to a permanently unspendable UTXO.
      #
      # Aliasing through <tt>load_const "@ref:"</tt> -- the same idiom
      # <tt>let x = y</tt> and the increment/decrement lowerings already use --
      # makes the arm's stack effect +1 and copies the parent slot instead of
      # trying to move it. The alias is only emitted when the result was NOT
      # produced inside the arm, so every arm that already ended on its own
      # result keeps its exact bytes.
      #
      # @param e [Expression]
      # @return [void]
      def _lower_ternary_arm(e)
        ref = lower_expr_to_ref(e)
        return if !bindings.empty? && bindings.last.name == ref

        emit(Frontend._make_load_const_string("@ref:#{ref}"))
      end
      # Called on the ARM's sub-context from `_lower_ternary_expr`, so it has to
      # cross an object boundary the way `lower_expr_to_ref` does.
      public :_lower_ternary_arm

      def _lower_ternary_expr(e)
        cond_ref = lower_expr_to_ref(e.condition)

        then_ctx = sub_context
        then_ctx._lower_ternary_arm(e.consequent)
        sync_counter(then_ctx)

        else_ctx = sub_context
        else_ctx._lower_ternary_arm(e.alternate)
        sync_counter(else_ctx)

        emit(IR::ANFValue.new(kind: "if").tap do |v|
          v.cond = cond_ref
          v.then = then_ctx.bindings
          v.else_ = else_ctx.bindings
        end)
      end

      # @param e [IncrementExpr]
      # @return [String]
      def _lower_increment_expr(e)
        operand_ref = lower_expr_to_ref(e.operand)
        one_ref = emit(Frontend._make_load_const_int(1))
        result = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
          v.op = "+"
          v.left = operand_ref
          v.right = one_ref
        end)

        # If the operand is a named variable, update it
        if e.operand.is_a?(Identifier)
          emit_named(e.operand.name, Frontend._make_load_const_string("@ref:#{result}"))
        end
        if e.operand.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(e.operand.property, result))
        end

        e.prefix ? result : operand_ref
      end

      # @param e [DecrementExpr]
      # @return [String]
      def _lower_decrement_expr(e)
        operand_ref = lower_expr_to_ref(e.operand)
        one_ref = emit(Frontend._make_load_const_int(1))
        result = emit(IR::ANFValue.new(kind: "bin_op").tap do |v|
          v.op = "-"
          v.left = operand_ref
          v.right = one_ref
        end)

        # If the operand is a named variable, update it
        if e.operand.is_a?(Identifier)
          emit_named(e.operand.name, Frontend._make_load_const_string("@ref:#{result}"))
        end
        if e.operand.is_a?(PropertyAccessExpr)
          emit(Frontend._make_update_prop(e.operand.property, result))
        end

        e.prefix ? result : operand_ref
      end
    end # class LoweringContext

    # -------------------------------------------------------------------
    # ANFValue constructors (module-level helpers)
    # -------------------------------------------------------------------

    # Number.MAX_SAFE_INTEGER (2**53 - 1) -- the largest magnitude a bare JSON
    # number survives. int64 is NOT the boundary: 9_007_199_254_740_993 fits
    # int64 but comes back as ...992 from any double-backed JSON reader.
    JS_MAX_SAFE_INTEGER_LOAD_CONST = 9_007_199_254_740_991

    # Canonical IR-JSON encoding of an integer: the bare integer when a JSON
    # number carries it losslessly, else the JS BigInt `"<n>n"` decimal
    # string. Mirrors compilers/go/ir/types.go::BigIntToRawJSON and
    # compilers/python/runar_compiler/ir/types.py::bigint_json_value.
    #
    # @param val [Integer]
    # @return [Integer, String]
    def self._bigint_json_value(val)
      return val if val.abs <= JS_MAX_SAFE_INTEGER_LOAD_CONST

      "#{val}n"
    end

    # @param val [Integer]
    # @return [IR::ANFValue]
    def self._make_load_const_int(val)
      # JSON numbers in JavaScript are IEEE-754 doubles (~53 bits of integer
      # precision), and Go's encoding/json silently degrades JSON numbers
      # above 2^53 into scientific notation. Emit values a bare JSON number
      # cannot carry as a quoted decimal string with the canonical JS BigInt
      # `n` suffix so 256-bit constants (e.g. the secp256k1 group order
      # used in schnorr-zkp's s-bound assert) survive the JSON round-trip
      # losslessly AND so consuming IR decoders can distinguish a decimal-
      # encoded big integer from a hex-encoded ByteString literal. Mirrors
      # compilers/python/runar_compiler/frontend/anf_lower.py::_make_load_const_int
      # and compilers/go/frontend/anf_lower.go::makeLoadConstInt.
      raw = JSON.generate(_bigint_json_value(val))
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_big_int = val
        v.const_int = val
      end
    end

    # @param val [Boolean]
    # @return [IR::ANFValue]
    def self._make_load_const_bool(val)
      raw = JSON.generate(val)
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_bool = val
      end
    end

    # @param val [String]
    # @return [IR::ANFValue]
    def self._make_load_const_string(val)
      raw = JSON.generate(val)
      IR::ANFValue.new(kind: "load_const").tap do |v|
        v.raw_value = raw
        v.const_string = val
      end
    end

    # @param func_name [String]
    # @param args [Array<String>]
    # @return [IR::ANFValue]
    def self._make_call(func_name, args)
      IR::ANFValue.new(kind: "call").tap do |v|
        v.func = func_name
        v.args = args
      end
    end

    # Append the canonical result block to one arm of an if-statement: a copy
    # of every declared result, in the declared order, rebound under its own
    # name. This is what makes the +if+ node's +results+ contract true rather
    # than hoped-for.
    #
    # Two passes on purpose. Pass 1 always COPIES: +@ref:<local>+ resolves to
    # the arm's own new value if it rebound one, else to the enclosing scope's
    # value, and either way stack lowering picks (never rolls) it, because a
    # declared result is outer-protected. Pass 2 always CONSUMES, because the
    # temps are bound in this arm and this is their last use. The arm's stack
    # effect is therefore exactly +N regardless of which of the N results it
    # assigned. Semantically a no-op for the off-chain ANF interpreters.
    def self._append_branch_results(branch_ctx, result_names, props)
      result_names.each_with_index do |name, i|
        temp = "#{IR::MERGED_LOCAL_TEMP_PREFIX}#{i}"
        if props.include?(name)
          branch_ctx.emit_named(temp, IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = name })
        else
          branch_ctx.emit_named(temp, _make_load_const_string("@ref:#{name}"))
        end
      end
      result_names.each_with_index do |name, i|
        temp = "#{IR::MERGED_LOCAL_TEMP_PREFIX}#{i}"
        if props.include?(name)
          branch_ctx.emit(_make_update_prop(name, temp))
        else
          branch_ctx.emit_named(name, _make_load_const_string("@ref:#{temp}"))
        end
      end
    end

    # Concatenate a branch's output refs (state then data, in
    # declaration order) into a single bytes-ref appended to the
    # branch's bindings. If the branch has no outputs, emits an empty
    # +load_const+ so the branch still leaves one item on the stack —
    # required to balance the if's branch shapes when the OTHER
    # branch has outputs. 2026-04-30 audit finding F2 fix.
    def self._append_branch_output_concat(branch_ctx)
      all_refs = branch_ctx.get_add_output_refs.dup
      all_refs.concat(branch_ctx.get_add_data_output_refs)
      if all_refs.empty?
        return branch_ctx.emit(_make_load_const_string(""))
      end
      return all_refs[0] if all_refs.length == 1
      accumulated = all_refs[0]
      all_refs[1..].each do |ref|
        accumulated = branch_ctx.emit(_make_call("cat", [accumulated, ref]))
      end
      accumulated
    end

    # The identifiers still readable once statement +index+ of this block has
    # run: everything the following statements in this block read, plus whatever
    # the enclosing blocks read after this block.
    #
    # Used by +_lower_if_statement+ to tell a branch-merged local that is dead
    # after the +if+ (safe) from one that is still live (not representable
    # alongside a branch output -- see +_branch_output_rejection_reason+).
    def self._reads_after_statement(stmts, index, reads_after_block)
      reads = reads_after_block.dup
      stmts[(index + 1)..].each { |stmt| _collect_statement_reads(stmt, reads) }
      reads
    end

    # Collect every identifier a statement READS. The +x+ in +x = expr+ is a
    # write, not a read, so a plain identifier assignment target is skipped;
    # every other target form can still read locals.
    def self._collect_statement_reads(stmt, out)
      case stmt
      when VariableDeclStmt
        _collect_expression_reads(stmt.init, out)
      when AssignmentStmt
        _collect_expression_reads(stmt.target, out) unless stmt.target.is_a?(Identifier)
        _collect_expression_reads(stmt.value, out)
      when IfStmt
        _collect_expression_reads(stmt.condition, out)
        (stmt.then || []).each { |inner| _collect_statement_reads(inner, out) }
        (stmt.else_ || []).each { |inner| _collect_statement_reads(inner, out) }
      when ForStmt
        _collect_statement_reads(stmt.init, out) if stmt.init
        _collect_expression_reads(stmt.condition, out)
        _collect_statement_reads(stmt.update, out) if stmt.update
        (stmt.body || []).each { |inner| _collect_statement_reads(inner, out) }
      when ReturnStmt
        _collect_expression_reads(stmt.value, out)
      when ExpressionStmt
        _collect_expression_reads(stmt.expr, out)
      end
    end

    # Collect every identifier an expression reads.
    def self._collect_expression_reads(expr, out)
      return if expr.nil?

      case expr
      when Identifier
        out.add(expr.name)
      when BinaryExpr
        _collect_expression_reads(expr.left, out)
        _collect_expression_reads(expr.right, out)
      when UnaryExpr
        _collect_expression_reads(expr.operand, out)
      when CallExpr
        (expr.args || []).each { |a| _collect_expression_reads(a, out) }
      when MethodCallExpr
        (expr.args || []).each { |a| _collect_expression_reads(a, out) }
      when MemberExpr
        _collect_expression_reads(expr.object, out)
      when TernaryExpr
        _collect_expression_reads(expr.condition, out)
        _collect_expression_reads(expr.consequent, out)
        _collect_expression_reads(expr.alternate, out)
      when IndexAccessExpr
        _collect_expression_reads(expr.object, out)
        _collect_expression_reads(expr.index, out)
      when IncrementExpr, DecrementExpr
        _collect_expression_reads(expr.operand, out)
      when ArrayLiteralExpr
        (expr.elements || []).each { |e| _collect_expression_reads(e, out) }
      end
      # Literals and `this.x` property access read no locals.
    end

    # Why an +if+ whose arms declare outputs cannot be represented -- or +nil+
    # when it can. The result is the reason clause the diagnostic embeds.
    #
    # An +if+ expression carries exactly ONE value, and when an arm emits an
    # output that value is already spoken for: it is the output bytes the
    # continuation hash consumes (+_append_branch_output_concat+). Anything ELSE
    # the arm leaves behind breaks one of two invariants nothing downstream
    # enforces:
    #
    # INV-A:: the parent registers the if-expression's value as the branch's
    #         contribution to the continuation hash, so "the branch's output
    #         bytes" really means "whatever the arm's LAST binding is". A binding
    #         that lands after the output -- a rebound local, a property write --
    #         silently replaces the serialized output with an unrelated value,
    #         and the residue drain then physically drops the real output.
    # INV-B:: an arm that emits an output AND leaves any other slot the parent
    #         can still name -- a property write anywhere in the arm, or a
    #         rebound local that is still read after the +if+ -- leaves 2+
    #         results against the ONE stack-map name the stack lowerer
    #         registers, desyncing the parent stack by a slot from there on.
    #
    # Neither is visible off-chain, so both shipped as permanently unspendable
    # locking scripts. Refuse at compile time rather than emit one. See
    # packages/runar-testing/src/__tests__/branch-output-terminal-value-vm.test.ts
    # for the real-Script-VM proof of each shape.
    #
    # The clauses are checked in a fixed order so all seven tiers report the same
    # reason for a source that trips more than one.
    def self._branch_output_rejection_reason(
      then_ctx, else_ctx, then_output_bytes, else_output_bytes, merged_locals, reads_after
    )
      # 1. Two or more merged locals: normalising them would need a
      #    multi-result +if+ node, and the arms' single value is already the
      #    output concat.
      if merged_locals.length >= 2
        return "merges #{merged_locals.length} local variables " \
               "(#{merged_locals.join(', ')})"
      end

      arms = [["then", then_ctx, then_output_bytes], ["else", else_ctx, else_output_bytes]]

      # 2. INV-A: the arm's terminal binding must BE its output bytes.
      arms.each do |label, branch_ctx, output_bytes|
        if branch_ctx.bindings.empty? || branch_ctx.bindings.last.name != output_bytes
          return "continues past its output in the #{label}-branch"
        end
      end

      # 3. INV-B: a property write leaves a slot the parent can still name,
      #    wherever in the arm it sits.
      written_props = []
      arms.each { |_, branch_ctx, _| _collect_updated_props(branch_ctx.bindings, written_props) }
      unless written_props.empty?
        return "assigns contract properties (#{written_props.join(', ')}) inside the branch"
      end

      # 4. INV-B: a rebound local that survives the +if+ is protected from being
      #    rolled away, so the arm ends one slot deeper than lowerIf accounts
      #    for.
      live_merged = merged_locals.select { |name| reads_after.include?(name) }
      unless live_merged.empty?
        return "reassigns local variables read after it (#{live_merged.join(', ')})"
      end

      nil
    end

    # Append every property name an ANF binding list assigns, including the ones
    # nested inside an +if+ arm or a +loop+ body -- a nested write is just as
    # much a named slot the enclosing arm leaves behind.
    def self._collect_updated_props(bindings, out)
      bindings.each do |binding|
        value = binding.value
        case value.kind
        when "update_prop"
          out << value.name unless out.include?(value.name)
        when "if"
          _collect_updated_props(value.then || [], out)
          _collect_updated_props(value.else_ || [], out)
        when "loop"
          _collect_updated_props(value.body || [], out)
        end
      end
    end

    # @param value_ref [String]
    # @return [IR::ANFValue]
    def self._make_assert(value_ref)
      raw = JSON.generate(value_ref)
      IR::ANFValue.new(kind: "assert").tap do |v|
        v.raw_value = raw
        v.value_ref = value_ref
      end
    end

    # Build the auto-injected stateful-continuation hash-equality assert.
    # Carries +is_auto_injected_state_check = true+ so off-chain SDK
    # interpreters can skip the equality check via a direct marker lookup
    # instead of structural / taint heuristics that misfire on developer
    # code with identical IR shape (covenant rules).
    # @param value_ref [String]
    # @return [IR::ANFValue]
    def self._make_auto_injected_state_check_assert(value_ref)
      raw = JSON.generate(value_ref)
      IR::ANFValue.new(kind: "assert").tap do |v|
        v.raw_value = raw
        v.value_ref = value_ref
        v.is_auto_injected_state_check = true
      end
    end

    # @param name [String]
    # @param value_ref [String]
    # @return [IR::ANFValue]
    def self._make_update_prop(name, value_ref)
      raw = JSON.generate(value_ref)
      IR::ANFValue.new(kind: "update_prop").tap do |v|
        v.name = name
        v.raw_value = raw
        v.value_ref = value_ref
      end
    end

    # -------------------------------------------------------------------
    # State mutation analysis
    # -------------------------------------------------------------------

    # Determine whether a method mutates any mutable (non-readonly) property.
    # Conservative: if ANY code path can mutate state, returns true. Walks
    # the private-method call graph so a public method that delegates the
    # mutation to a private helper is correctly classified — fix for the
    # 2026-04-30 audit's F1 finding.
    def self._method_mutates_state(method, contract)
      mutable_props = Set.new
      contract.properties.each do |p|
        mutable_props.add(p.name) unless p.readonly
      end
      return false if mutable_props.empty?
      _body_mutates_state(method.body, mutable_props, contract, [].to_set)
    end
    private_class_method :_method_mutates_state

    # @param stmts [Array<Statement>]
    # @param mutable_props [Set<String>]
    # @param contract [ContractNode]
    # @param seen [Set<String>] private methods currently on the recursion stack
    # @return [Boolean]
    def self._body_mutates_state(stmts, mutable_props, contract, seen)
      stmts.any? { |stmt| _stmt_mutates_state(stmt, mutable_props, contract, seen) }
    end
    private_class_method :_body_mutates_state

    # @return [Boolean]
    def self._stmt_mutates_state(stmt, mutable_props, contract, seen)
      if stmt.is_a?(AssignmentStmt)
        if stmt.target.is_a?(PropertyAccessExpr)
          return mutable_props.include?(stmt.target.property)
        end
        return false
      end

      if stmt.is_a?(ExpressionStmt)
        return _expr_mutates_state(stmt.expr, mutable_props, contract, seen)
      end

      if stmt.is_a?(IfStmt)
        return true if _body_mutates_state(stmt.then, mutable_props, contract, seen)
        if stmt.else_ && stmt.else_.any?
          return true if _body_mutates_state(stmt.else_, mutable_props, contract, seen)
        end
        return false
      end

      if stmt.is_a?(ForStmt)
        if stmt.update && _stmt_mutates_state(stmt.update, mutable_props, contract, seen)
          return true
        end
        return _body_mutates_state(stmt.body, mutable_props, contract, seen)
      end

      if stmt.is_a?(ReturnStmt) && stmt.value
        return _expr_mutates_state(stmt.value, mutable_props, contract, seen)
      end

      false
    end
    private_class_method :_stmt_mutates_state

    # @return [Boolean]
    def self._expr_mutates_state(expr, mutable_props, contract, seen)
      return false if expr.nil?
      if expr.is_a?(IncrementExpr)
        if expr.operand.is_a?(PropertyAccessExpr)
          return mutable_props.include?(expr.operand.property)
        end
      end
      if expr.is_a?(DecrementExpr)
        if expr.operand.is_a?(PropertyAccessExpr)
          return mutable_props.include?(expr.operand.property)
        end
      end
      if expr.is_a?(CallExpr)
        target = _resolve_private_method(expr.callee, contract)
        if target && !seen.include?(target.name)
          new_seen = seen.dup.add(target.name)
          return true if _body_mutates_state(target.body, mutable_props, contract, new_seen)
        end
      end
      false
    end
    private_class_method :_expr_mutates_state

    # Resolve a CallExpr callee to a private method on the contract, or
    # nil if the callee is a builtin / external / unresolved.
    def self._resolve_private_method(callee, contract)
      return nil if callee.nil?
      name =
        if callee.is_a?(PropertyAccessExpr)
          callee.property
        elsif callee.is_a?(MemberExpr)
          callee.property
        elsif callee.is_a?(Identifier)
          callee.name
        end
      return nil if name.nil?
      contract.methods.find { |m| m.name == name && m.visibility != "public" }
    end
    private_class_method :_resolve_private_method

    # -------------------------------------------------------------------
    # addOutput detection for determining change output necessity
    # -------------------------------------------------------------------

    # Check if a method body contains any this.addOutput() calls,
    # including those reachable via private-helper calls.
    def self._method_has_add_output(method, contract)
      _body_has_add_output(method.body, contract, [].to_set)
    end
    private_class_method :_method_has_add_output

    # @return [Boolean]
    def self._body_has_add_output(stmts, contract, seen)
      stmts.any? { |stmt| _stmt_has_add_output(stmt, contract, seen) }
    end
    private_class_method :_body_has_add_output

    # @return [Boolean]
    def self._stmt_has_add_output(stmt, contract, seen)
      if stmt.is_a?(ExpressionStmt)
        return _expr_has_add_output(stmt.expr, contract, seen)
      end
      if stmt.is_a?(IfStmt)
        return true if _body_has_add_output(stmt.then, contract, seen)
        if stmt.else_ && stmt.else_.any?
          return true if _body_has_add_output(stmt.else_, contract, seen)
        end
        return false
      end
      if stmt.is_a?(ForStmt)
        return _body_has_add_output(stmt.body, contract, seen)
      end
      # Ruby's parser_ruby promotes a private method's trailing
      # ExpressionStmt to a ReturnStmt for implicit-return semantics, so
      # `add_output(...)` calls in helper bodies wind up here. Walk the
      # return value the same way an ExpressionStmt would be walked.
      if stmt.is_a?(ReturnStmt) && stmt.value
        return _expr_has_add_output(stmt.value, contract, seen)
      end
      false
    end
    private_class_method :_stmt_has_add_output

    # @return [Boolean]
    def self._expr_has_add_output(expr, contract, seen)
      return false if expr.nil?
      if expr.is_a?(CallExpr)
        callee = expr.callee
        if callee.is_a?(PropertyAccessExpr) && %w[addOutput addRawOutput].include?(callee.property)
          return true
        end
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           %w[addOutput addRawOutput].include?(callee.property)
          return true
        end
        target = _resolve_private_method(callee, contract)
        if target && !seen.include?(target.name)
          new_seen = seen.dup.add(target.name)
          return true if _body_has_add_output(target.body, contract, new_seen)
        end
      end
      false
    end
    private_class_method :_expr_has_add_output

    # -------------------------------------------------------------------
    # addDataOutput detection (distinct from state outputs)
    # -------------------------------------------------------------------

    # Check if a method body contains any this.addDataOutput() calls,
    # including those reachable via private-helper calls.
    def self._method_has_add_data_output(method, contract)
      _body_has_add_data_output(method.body, contract, [].to_set)
    end
    private_class_method :_method_has_add_data_output

    # @return [Boolean]
    def self._body_has_add_data_output(stmts, contract, seen)
      stmts.any? { |stmt| _stmt_has_add_data_output(stmt, contract, seen) }
    end
    private_class_method :_body_has_add_data_output

    # @return [Boolean]
    def self._stmt_has_add_data_output(stmt, contract, seen)
      if stmt.is_a?(ExpressionStmt)
        return _expr_has_add_data_output(stmt.expr, contract, seen)
      end
      if stmt.is_a?(IfStmt)
        return true if _body_has_add_data_output(stmt.then, contract, seen)
        if stmt.else_ && stmt.else_.any?
          return true if _body_has_add_data_output(stmt.else_, contract, seen)
        end
        return false
      end
      if stmt.is_a?(ForStmt)
        return _body_has_add_data_output(stmt.body, contract, seen)
      end
      if stmt.is_a?(ReturnStmt) && stmt.value
        return _expr_has_add_data_output(stmt.value, contract, seen)
      end
      false
    end
    private_class_method :_stmt_has_add_data_output

    # @return [Boolean]
    def self._expr_has_add_data_output(expr, contract, seen)
      return false if expr.nil?
      if expr.is_a?(CallExpr)
        callee = expr.callee
        if callee.is_a?(PropertyAccessExpr) && callee.property == "addDataOutput"
          return true
        end
        if callee.is_a?(MemberExpr) &&
           callee.object.is_a?(Identifier) &&
           callee.object.name == "this" &&
           callee.property == "addDataOutput"
          return true
        end
        target = _resolve_private_method(callee, contract)
        if target && !seen.include?(target.name)
          new_seen = seen.dup.add(target.name)
          return true if _body_has_add_data_output(target.body, contract, new_seen)
        end
      end
      false
    end
    private_class_method :_expr_has_add_data_output

    # -------------------------------------------------------------------
    # Loop shape extraction (#121)
    # -------------------------------------------------------------------

    # Resolve a for-statement's compile-time loop shape: start value, step
    # direction, and iteration count. Supports counting-up and counting-down
    # loops:
    #   for (let i = 0n; i < 10n; i++)  -> start 0, step +1, count 10
    #   for (let i = 1n; i <= 3n; i++)  -> start 1, step +1, count 3
    #   for (let i = 3n; i > 0n; i--)   -> start 3, step -1, count 3
    #   for (let i = 3n; i >= 1n; i--)  -> start 3, step -1, count 3
    #
    # The loop is unrolled +count+ times; on iteration +i+ the iterator holds
    # +start + i*step+. Start and bound must be compile-time integer literals.
    #
    # @param stmt [ForStmt]
    # @return [Hash] { start: Integer, step: Integer, count: Integer }
    def self._extract_loop_shape(stmt)
      start = _extract_bigint_value(stmt.init&.init)
      if start.nil?
        raise "Cannot determine loop start at compile time. " \
              "For-loop iterators must start at an integer literal."
      end

      unless stmt.condition.is_a?(BinaryExpr)
        raise "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
      end
      op = stmt.condition.op
      bound = _extract_bigint_value(stmt.condition.right)
      if bound.nil?
        raise "Cannot determine loop bound at compile time. For-loop bounds must be integer literals."
      end

      step = _extract_loop_step(stmt)

      # Count = number of iterations before the condition first turns false.
      if step == 1
        case op
        when "<"  then count = bound - start
        when "<=" then count = bound - start + 1
        else
          raise "For loop counting up (i++) must use '<' or '<=' (got '#{op}')."
        end
      else
        case op
        when ">"  then count = start - bound
        when ">=" then count = start - bound + 1
        else
          raise "For loop counting down (i--) must use '>' or '>=' (got '#{op}')."
        end
      end

      { start: start, step: step, count: [0, count].max }
    end

    # Determine the iterator step direction (+1 / -1) from the for-statement's
    # update clause, falling back to the condition direction. Only unit steps
    # are supported.
    #
    # @param stmt [ForStmt]
    # @return [Integer] +1 or -1
    def self._extract_loop_step(stmt)
      update = stmt.update
      if update.is_a?(ExpressionStmt)
        e = update.expr
        return 1 if e.is_a?(IncrementExpr)
        return -1 if e.is_a?(DecrementExpr)
      end
      # Fall back to the comparison direction for other unit-step spellings
      # (e.g. `i = i + 1n`): `<`/`<=` counts up, `>`/`>=` counts down.
      if stmt.condition.is_a?(BinaryExpr)
        op = stmt.condition.op
        return -1 if op == ">" || op == ">="
      end
      1
    end

    # @param expr [Expression, nil]
    # @return [Integer, nil]
    def self._extract_bigint_value(expr)
      return nil if expr.nil?
      return expr.value if expr.is_a?(BigIntLiteral)
      if expr.is_a?(UnaryExpr) && expr.op == "-"
        inner = _extract_bigint_value(expr.operand)
        return -inner unless inner.nil?
      end
      nil
    end
    private_class_method :_extract_bigint_value

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    # Check whether a statement list always terminates with a return statement.
    # @param stmts [Array<Statement>]
    # @return [Boolean]
    def self._branch_ends_with_return(stmts)
      return false if stmts.nil? || stmts.empty?
      last = stmts.last
      return true if last.is_a?(ReturnStmt)
      # Also handle if-else where both branches return
      if last.is_a?(IfStmt) && last.else_ && last.else_.any?
        return _branch_ends_with_return(last.then) && _branch_ends_with_return(last.else_)
      end
      false
    end

    # Convert a type node to its string representation.
    # @param node [TypeNode, nil]
    # @return [String]
    def self._type_node_to_string(node)
      return "<unknown>" if node.nil?
      return node.name if node.is_a?(PrimitiveType)
      return "#{_type_node_to_string(node.element)}[]" if node.is_a?(FixedArrayType)
      return node.name if node.is_a?(CustomType)
      "<unknown>"
    end

    # -------------------------------------------------------------------
    # Post-ANF pass: lift update_prop from if-else branches
    # -------------------------------------------------------------------
    #
    # Mirrors the TypeScript reference compiler's liftBranchUpdateProps.
    # Transforms if-else chains where each branch ends with update_prop
    # into flat conditional assignments. This is critical for stateful
    # contracts because Bitcoin Script requires ALL state fields to be
    # explicitly on the stack after method execution.
    #
    # Before:
    #   if (pos === 0) { this.c0 = turn; }
    #   else if (pos === 1) { this.c1 = turn; }
    #   else { assert(false); }
    #
    # After:
    #   this.c0 = (pos === 0)            ? turn : this.c0;
    #   this.c1 = (!cond0 && pos === 1)  ? turn : this.c1;

    # Find the max temp index (e.g. t47 -> 47) in a binding tree.
    def self._max_temp_index(bindings)
      max = -1
      bindings.each do |b|
        if b.name.match?(/\At\d+\z/)
          n = b.name[1..].to_i
          max = n if n > max
        end
        v = b.value
        if v.kind == "if"
          t = _max_temp_index(v.then || [])
          max = t if t > max
          e = _max_temp_index(v.else_ || [])
          max = e if e > max
        elsif v.kind == "loop"
          t = _max_temp_index(v.body || [])
          max = t if t > max
        end
      end
      max
    end
    private_class_method :_max_temp_index

    # Check if all bindings are side-effect-free (safe to hoist).
    def self._all_side_effect_free?(bindings)
      bindings.all? do |b|
        %w[load_prop load_param load_const bin_op unary_op].include?(b.value.kind)
      end
    end
    private_class_method :_all_side_effect_free?

    # Extract the update_prop target from a branch's last binding.
    # Returns { prop_name:, value_bindings:, value_ref: } or nil.
    def self._extract_branch_update(bindings)
      return nil if bindings.empty?

      last = bindings.last
      return nil unless last.value.kind == "update_prop"

      value_bindings = bindings[0...-1]
      return nil unless _all_side_effect_free?(value_bindings)

      {
        prop_name: last.value.name,
        value_bindings: value_bindings,
        value_ref: last.value.value_ref || last.value.raw_value
      }
    end
    private_class_method :_extract_branch_update

    # Check if an else branch is just assert(false) — unreachable dead code.
    def self._assert_false_else?(bindings)
      return false if bindings.empty?

      last = bindings.last
      return false unless last.value.kind == "assert"

      assert_ref = last.value.value_ref || last.value.raw_value
      ref_binding = bindings.find { |b| b.name == assert_ref }
      if ref_binding && ref_binding.value.kind == "load_const"
        # Check raw_value (JSON false literal) or const_bool (decoded boolean)
        return true if ref_binding.value.raw_value == false
        return true if ref_binding.value.const_bool == false
      end

      false
    end
    private_class_method :_assert_false_else?

    # An arm with its declared-results block removed.
    #
    # +_append_branch_results+ adds exactly <tt>2 * results.length</tt> trailing
    # bindings to each arm of an +if+ that declares results. They are a
    # materialisation mechanism, not program logic, and they hide the arm's real
    # shape from this pass. A dispatch chain's deepest +if+ is nested by
    # definition, so it declares results; without this the enclosing chain stops
    # being recognised and TicTacToe's position dispatch loses the C20 lift (an
    # unspendable +move+ script).
    def self._strip_declared_results(bindings, results)
      n = results.nil? ? 0 : results.length
      return bindings if n.zero?

      cut = bindings.length - (2 * n)
      cut = 0 if cut.negative?
      bindings[0...cut]
    end
    private_class_method :_strip_declared_results

    # Recursively collect update branches from a nested if-else chain.
    def self._collect_update_branches(if_cond, then_bindings, else_bindings)
      then_update = _extract_branch_update(then_bindings)
      return nil unless then_update

      branches = [{
        cond_setup_bindings: [],
        cond_ref: if_cond,
        **then_update
      }]

      return nil if else_bindings.nil? || else_bindings.empty?

      # Check if else is another if (else-if chain)
      last_else = else_bindings.last
      if last_else.value.kind == "if"
        inner_if = last_else.value
        cond_setup = else_bindings[0...-1]
        return nil unless _all_side_effect_free?(cond_setup)

        inner_branches = _collect_update_branches(
          inner_if.cond,
          _strip_declared_results(inner_if.then || [], inner_if.results),
          _strip_declared_results(inner_if.else_ || [], inner_if.results)
        )
        return nil unless inner_branches

        # Prepend condition setup to first inner branch
        inner_branches[0][:cond_setup_bindings] =
          cond_setup + inner_branches[0][:cond_setup_bindings]
        branches.concat(inner_branches)
        return branches
      end

      # Otherwise, else branch should end with update_prop (final else)
      else_update = _extract_branch_update(else_bindings)
      if else_update
        branches << { cond_setup_bindings: [], cond_ref: nil, **else_update }
        return branches
      end

      # Handle unreachable else: assert(false) as dead code
      return branches if _assert_false_else?(else_bindings)

      nil
    end
    private_class_method :_collect_update_branches

    # Remap temp references in an ANF value according to a name mapping.
    def self._remap_value_refs(value, map)
      r = ->(ref) { map[ref] || ref }

      case value.kind
      when "load_param", "load_prop", "get_state_script"
        value
      when "load_const"
        if value.raw_value.is_a?(String) && value.raw_value.start_with?("@ref:")
          target = value.raw_value[5..]
          remapped = map[target]
          if remapped
            new_v = _clone_anf_value(value)
            new_v.raw_value = "@ref:#{remapped}"
            return new_v
          end
        end
        value
      when "bin_op"
        new_v = _clone_anf_value(value)
        new_v.left = r.call(value.left)
        new_v.right = r.call(value.right)
        new_v
      when "unary_op"
        new_v = _clone_anf_value(value)
        new_v.operand = r.call(value.operand)
        new_v
      when "call"
        new_v = _clone_anf_value(value)
        new_v.args = (value.args || []).map { |a| r.call(a) }
        new_v
      when "method_call"
        new_v = _clone_anf_value(value)
        new_v.object = r.call(value.object)
        new_v.args = (value.args || []).map { |a| r.call(a) }
        new_v
      when "assert"
        new_v = _clone_anf_value(value)
        ref = value.value_ref || value.raw_value
        new_v.value_ref = r.call(ref) if ref
        new_v.raw_value = r.call(ref) if ref
        new_v
      when "update_prop"
        new_v = _clone_anf_value(value)
        ref = value.value_ref || value.raw_value
        new_v.value_ref = r.call(ref) if ref
        new_v.raw_value = r.call(ref) if ref
        new_v
      when "if"
        new_v = _clone_anf_value(value)
        new_v.cond = r.call(value.cond)
        new_v
      when "check_preimage", "deserialize_state"
        new_v = _clone_anf_value(value)
        new_v.preimage = r.call(value.preimage)
        new_v
      when "add_output"
        new_v = _clone_anf_value(value)
        new_v.satoshis = r.call(value.satoshis)
        new_v.state_values = (value.state_values || []).map { |s| r.call(s) }
        new_v.preimage = r.call(value.preimage)
        new_v
      when "add_raw_output"
        new_v = _clone_anf_value(value)
        new_v.satoshis = r.call(value.satoshis)
        new_v.script_bytes = r.call(value.script_bytes)
        new_v
      when "add_data_output"
        new_v = _clone_anf_value(value)
        new_v.satoshis = r.call(value.satoshis)
        new_v.script_bytes = r.call(value.script_bytes)
        new_v
      when "loop"
        # No top-level refs to remap (body is walked by the caller).
        value
      when "array_literal"
        new_v = _clone_anf_value(value)
        new_v.elements = (value.elements || []).map { |e| r.call(e) }
        new_v
      when "raw_script"
        # Opaque byte span -- no SSA operand refs to remap.
        value
      else
        # Exhaustiveness guard. If a new ANFValue variant is added without
        # wiring it through this dispatch, fail loudly so the regression is
        # caught at the first call site instead of corrupting downstream IR.
        raise ::RunarCompiler::IR::UnknownANFKindError.new(value.kind, "anf-lower.remapValueRefs")
      end
    end
    private_class_method :_remap_value_refs

    # Shallow clone an ANFValue.
    def self._clone_anf_value(v)
      new_v = IR::ANFValue.new(kind: v.kind)
      new_v.name = v.name
      new_v.raw_value = v.raw_value
      new_v.const_string = v.const_string
      new_v.const_big_int = v.const_big_int
      new_v.const_bool = v.const_bool
      new_v.const_int = v.const_int
      new_v.op = v.op
      new_v.left = v.left
      new_v.right = v.right
      new_v.result_type = v.result_type
      new_v.operand = v.operand
      new_v.func = v.func
      new_v.args = v.args
      new_v.object = v.object
      new_v.method = v.method
      new_v.cond = v.cond
      new_v.then = v.then
      new_v.else_ = v.else_
      new_v.count = v.count
      new_v.iter_var = v.iter_var
      new_v.body = v.body
      new_v.start = v.start
      new_v.step = v.step
      new_v.value_ref = v.value_ref
      new_v.preimage = v.preimage
      new_v.satoshis = v.satoshis
      new_v.state_values = v.state_values
      new_v.script_bytes = v.script_bytes
      new_v.elements = v.elements
      new_v.bytes = v.bytes
      new_v.in_arity = v.in_arity
      new_v.out_arity = v.out_arity
      new_v
    end
    private_class_method :_clone_anf_value

    # Transform if-bindings whose branches all end with update_prop into
    # flat conditional assignments.
    def self._lift_branch_update_props(bindings)
      next_idx = _max_temp_index(bindings) + 1
      fresh = -> { name = "t#{next_idx}"; next_idx += 1; name }

      result = []

      bindings.each do |binding|
        unless binding.value.kind == "if"
          result << binding
          next
        end

        if_val = binding.value
        branches = _collect_update_branches(
          if_val.cond,
          _strip_declared_results(if_val.then || [], if_val.results),
          _strip_declared_results(if_val.else_ || [], if_val.results)
        )

        unless branches && branches.length >= 2
          result << binding
          next
        end

        # --- Transform: flatten into conditional assignments ---

        # 1. Hoist condition setup bindings with fresh names
        name_map = {}
        cond_refs = []

        branches.each do |branch|
          branch[:cond_setup_bindings].each do |csb|
            new_name = fresh.call
            name_map[csb.name] = new_name
            result << IR::ANFBinding.new(
              name: new_name,
              value: _remap_value_refs(csb.value, name_map)
            )
          end
          cond_refs << (branch[:cond_ref] ? (name_map[branch[:cond_ref]] || branch[:cond_ref]) : nil)
        end

        # 2. Compute effective condition for each branch
        effective_conds = []
        negated_conds = []

        branches.each_with_index do |_branch, i|
          if i == 0
            effective_conds << cond_refs[0]
            next
          end

          # Negate any prior conditions not yet negated
          (negated_conds.length...i).each do |j|
            next if cond_refs[j].nil?

            neg_name = fresh.call
            result << IR::ANFBinding.new(
              name: neg_name,
              value: IR::ANFValue.new(kind: "unary_op").tap do |v|
                v.op = "!"
                v.operand = cond_refs[j]
              end
            )
            negated_conds << neg_name
          end

          # AND all negated conditions together
          and_ref = negated_conds[0]
          (1...[i, negated_conds.length].min).each do |j|
            and_name = fresh.call
            result << IR::ANFBinding.new(
              name: and_name,
              value: IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "&&"
                v.left = and_ref
                v.right = negated_conds[j]
              end
            )
            and_ref = and_name
          end

          if cond_refs[i]
            # Middle branch: AND with own condition
            final_name = fresh.call
            result << IR::ANFBinding.new(
              name: final_name,
              value: IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "&&"
                v.left = and_ref
                v.right = cond_refs[i]
              end
            )
            effective_conds << final_name
          else
            # Final else: just the AND of negations
            effective_conds << and_ref
          end
        end

        # 2b. C20 -- preserve a dropped terminal `assert(false)` else.
        #
        # `_collect_update_branches` flattens a dispatch chain whose branches
        # each end in a single `update_prop` into this conditional-assignment
        # form. When the chain's terminal else is `assert(false)` it returns the
        # branches WITHOUT a catch-all final branch (every branch keeps a
        # non-nil cond_ref), dropping the abort. That assert(false) is the only
        # thing rejecting a selector value matching no branch: without it, an
        # unmatched selector leaves every property at its old value -- a
        # spendable NO-OP state continuation instead of a failed script (a
        # funds-safety bug). A real final else (`else { prop = ... }`) instead
        # yields a catch-all branch with a nil cond_ref and needs no guard. So
        # re-introduce the abort as `assert(cond0 || cond1 || ... || cond_{N-1})`
        # iff there is no catch-all (the last branch keeps a non-nil cond_ref).
        has_catch_all_else = branches.last[:cond_ref].nil?
        unless has_catch_all_else
          or_ref = cond_refs[0]
          (1...cond_refs.length).each do |i|
            or_name = fresh.call
            result << IR::ANFBinding.new(
              name: or_name,
              value: IR::ANFValue.new(kind: "bin_op").tap do |v|
                v.op = "||"
                v.left = or_ref
                v.right = cond_refs[i]
              end
            )
            or_ref = or_name
          end
          result << IR::ANFBinding.new(
            name: fresh.call,
            value: _make_assert(or_ref)
          )
        end

        # 3. For each branch, emit: load_old, conditional if-expression, update_prop
        branches.each_with_index do |branch, i|
          # Load old property value
          old_prop_ref = fresh.call
          result << IR::ANFBinding.new(
            name: old_prop_ref,
            value: IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = branch[:prop_name] }
          )

          # Remap value bindings for the then-branch
          branch_map = name_map.dup
          then_bindings = []
          branch[:value_bindings].each do |vb|
            new_name = fresh.call
            branch_map[vb.name] = new_name
            then_bindings << IR::ANFBinding.new(
              name: new_name,
              value: _remap_value_refs(vb.value, branch_map)
            )
          end

          # The then-branch value: remap the value_ref through branch_map
          then_value_ref = branch_map[branch[:value_ref]] || branch[:value_ref]
          # If there are no value_bindings, we need a load_prop for the value
          if then_bindings.empty?
            load_name = fresh.call
            then_bindings << IR::ANFBinding.new(
              name: load_name,
              value: IR::ANFValue.new(kind: "load_prop").tap { |v| v.name = "turn" }
            )
            # We need the actual turn value — use the value_ref from the branch
            # which points to a load_prop that was inside the original branch
            then_bindings = branch[:value_bindings].map do |vb|
              new_name = fresh.call
              branch_map[vb.name] = new_name
              IR::ANFBinding.new(
                name: new_name,
                value: _remap_value_refs(vb.value, branch_map)
              )
            end
            then_value_ref = branch_map[branch[:value_ref]] || branch[:value_ref]
          end

          # Else branch: keep old property value
          keep_name = fresh.call
          else_bindings = [
            IR::ANFBinding.new(
              name: keep_name,
              value: _make_load_const_string("@ref:#{old_prop_ref}")
            )
          ]

          # Emit conditional if-expression
          cond_if_ref = fresh.call
          result << IR::ANFBinding.new(
            name: cond_if_ref,
            value: IR::ANFValue.new(kind: "if").tap do |v|
              v.cond = effective_conds[i]
              v.then = then_bindings
              v.else_ = else_bindings
            end
          )

          # Emit update_prop
          result << IR::ANFBinding.new(
            name: fresh.call,
            value: IR::ANFValue.new(kind: "update_prop").tap do |v|
              v.name = branch[:prop_name]
              v.value_ref = cond_if_ref
              v.raw_value = cond_if_ref
            end
          )
        end
      end

      result
    end
    private_class_method :_lift_branch_update_props
  end
end
