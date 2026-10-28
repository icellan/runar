# frozen_string_literal: true

# ANF-level EC (elliptic curve) optimizer -- Pass 4.5.
#
# Applies algebraic simplification rules to EC intrinsic calls in the ANF IR,
# mirroring the TypeScript implementation in
# +packages/runar-compiler/src/optimizer/ec-optimize.ts+.
#
# Runs between ANF lowering (pass 4) and stack lowering (pass 5).
#
# Direct port of compilers/python/runar_compiler/frontend/anf_optimize.py.

require "json"
require "set"
require_relative "../ir/types"
require_relative "dce"
# Frontend._bigint_json_value — the canonical IR-JSON encoding for an integer,
# used by make_const_int for the folded EC scalars this pass emits.
require_relative "anf_lower"

module RunarCompiler
  module Frontend
    module ANFOptimize
      # -----------------------------------------------------------------
      # secp256k1 constants
      # -----------------------------------------------------------------

      CURVE_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
      GEN_X   = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
      GEN_Y   = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
      INFINITY_HEX = "0" * 128
      G_HEX = format("%064x%064x", GEN_X, GEN_Y)

      EC_FUNCS = %w[
        ecAdd ecMul ecMulGen ecNegate ecOnCurve
        ecModReduce ecEncodeCompressed ecMakePoint ecPointX ecPointY
      ].to_set.freeze

      # -----------------------------------------------------------------
      # Public API
      # -----------------------------------------------------------------

      # Return a new program with EC operations algebraically simplified.
      #
      # @param program [IR::ANFProgram]
      # @return [IR::ANFProgram]
      def self.optimize_ec(program)
        # Only deep-copy and run dead binding elimination if something changed.
        any_changed = program.methods.any? { |m| has_ec_calls?(m) }
        return program unless any_changed

        # N-097: the has-EC-call check above is only a fast path (a rule can
        # only fire on a top-level EC call). The gate is the TS reference's
        # (anf-ec.ts optimizeEC): dead binding elimination runs over EVERY
        # method iff a rewrite fired in ANY method, else the program is
        # returned untouched, dead bindings included.
        result = deep_copy_program(program)
        fired = false
        result.methods.each { |m| fired = true if optimize_method(m, result.properties) }
        return program unless fired

        # Dead binding elimination
        result.methods.each { |method| eliminate_dead_bindings(method) }
        result
      end

      # -----------------------------------------------------------------
      # Deep copy helpers
      # -----------------------------------------------------------------

      def self.deep_copy_program(program)
        IR::ANFProgram.new(
          contract_name: program.contract_name,
          properties: program.properties.map(&:dup),
          methods: program.methods.map { |m| deep_copy_method(m) },
          parent_class: program.parent_class
        )
      end
      private_class_method :deep_copy_program

      def self.deep_copy_method(method)
        IR::ANFMethod.new(
          name: method.name,
          params: method.params.map(&:dup),
          body: method.body.map { |b| deep_copy_binding(b) },
          is_public: method.is_public,
          # Issue #123: preserve the declared @sighash mode across EC deep-copy.
          sighash_type: method.sighash_type
        )
      end
      private_class_method :deep_copy_method

      def self.deep_copy_binding(binding)
        IR::ANFBinding.new(
          name: binding.name,
          value: deep_copy_value(binding.value),
          source_loc: binding.source_loc&.dup
        )
      end
      private_class_method :deep_copy_binding

      # The FIELDS that hold nested ANFBindings rather than scalars.
      NESTED_BINDING_FIELDS = %i[then else_ body].freeze

      # Copy every declared FIELD, then deep-copy the three that hold nested
      # bindings.
      #
      # This used to be a hand-written field-by-field list, and a hand-written
      # list is a list that silently loses fields as the IR grows: it was
      # missing +results+, +start+, +step+, +bytes+, +in_arity+, +out_arity+
      # and +is_auto_injected_state_check+. The +results+ drop was the one with
      # teeth (N-140) -- an EC-optimized contract lost its `if`'s declared
      # multi-result contract, and stack lowering then refused the node
      # ("declares no results") the moment DCE stopped deleting it outright.
      # Driving the copy off IR::ANFValue::FIELDS makes that class of loss
      # impossible rather than merely fixed once. (That is also what now
      # carries +preserve+ across -- issue #109's @embedAlways DCE opt-out
      # flag, which dead-binding elimination reads off THIS copy.)
      def self.deep_copy_value(v)
        nv = IR::ANFValue.new(kind: v.kind)
        IR::ANFValue::FIELDS.each do |f|
          next if NESTED_BINDING_FIELDS.include?(f)
          val = v.public_send(f)
          nv.public_send(:"#{f}=", val.is_a?(Array) ? val.dup : val)
        end
        nv.then  = v.then&.map  { |b| deep_copy_binding(b) }
        nv.else_ = v.else_&.map { |b| deep_copy_binding(b) }
        nv.body  = v.body&.map  { |b| deep_copy_binding(b) }
        nv
      end
      private_class_method :deep_copy_value

      # -----------------------------------------------------------------
      # EC call detection
      # -----------------------------------------------------------------

      def self.has_ec_calls?(method)
        method.body.any? do |binding|
          binding.value.kind == "call" && EC_FUNCS.include?(binding.value.func)
        end
      end
      private_class_method :has_ec_calls?

      # -----------------------------------------------------------------
      # Per-method optimization
      # -----------------------------------------------------------------

      # F-086: every name the method already uses -- binding names at any
      # depth (if/loop arms included), loop iteration variables, params, and
      # the contract's properties. A scalar-fusing rewrite mints a new
      # binding; ANF is single-assignment and stack lowering resolves a name
      # to its shallowest slot, so a minted name that is already in use
      # silently aliases the two values. +--ir+ input chooses these names
      # freely.
      def self.collect_used_names(method, properties)
        used = Set.new
        properties.each { |p| used << p.name }
        method.params.each { |p| used << p.name }
        walk = lambda do |bindings|
          (bindings || []).each do |b|
            used << b.name
            v = b.value
            case v.kind
            when "load_param", "load_prop"
              used << v.name if v.name
            when "if"
              walk.call(v.then)
              walk.call(v.else_)
            when "loop"
              used << v.iter_var if v.iter_var
              walk.call(v.body)
            end
          end
        end
        walk.call(method.body)
        used
      end
      private_class_method :collect_used_names

      # Binding name -> value, plus the method's rebound names (F-269, see
      # +canonical+).
      class ValueMap < Hash
        attr_reader :rebound

        def initialize(rebound)
          super()
          @rebound = rebound
        end
      end

      # F-269: every name bound more than once in the method -- binding names
      # at any depth (if/loop arms included) and loop iteration variables (the
      # TS collectReboundNames). +canonical+ never resolves through one.
      def self.collect_rebound_names(method)
        seen = Set.new
        rebound = Set.new
        bind = lambda do |name|
          if seen.include?(name)
            rebound << name
          else
            seen << name
          end
        end
        walk = lambda do |bindings|
          (bindings || []).each do |b|
            bind.call(b.name)
            v = b.value
            case v.kind
            when "if"
              walk.call(v.then)
              walk.call(v.else_)
            when "loop"
              bind.call(v.iter_var) if v.iter_var
              walk.call(v.body)
            end
          end
        end
        walk.call(method.body)
        rebound
      end
      private_class_method :collect_rebound_names

      def self.optimize_method(method, properties)
        value_map = ValueMap.new(collect_rebound_names(method))
        used_names = collect_used_names(method, properties)
        fired = false
        changed = true
        while changed
          changed = false
          new_body = []
          method.body.each do |binding|
            # +new_body+ doubles as the prelude list: a rule that folds a new
            # constant appends its binding here, i.e. immediately BEFORE the
            # binding being rewritten (see fresh_const_name).
            prelude_start = new_body.length
            optimized = try_optimize(binding.value, value_map, new_body, used_names, binding.name)
            if optimized
              # N-218: every helper a rewrite mints (the N-104/N-251 gate
              # bindings, the fused-scalar helper) takes the rewritten
              # binding's own source_loc, mirroring F-343 in the TS
              # reference (anf-ec.ts optimizeBodyOnce) -- it exists only
              # because of that source expression, and stack lowering maps
              # opcodes through binding.source_loc.
              new_body[prelude_start..].each { |helper| helper.source_loc = binding.source_loc }
              binding = IR::ANFBinding.new(
                name: binding.name,
                value: optimized,
                source_loc: binding.source_loc
              )
              changed = true
              fired = true
            end
            value_map[binding.name] = binding.value
            new_body << binding
          end
          method.body = new_body
        end

        fired
      end
      private_class_method :optimize_method

      # -----------------------------------------------------------------
      # Optimization rules
      # -----------------------------------------------------------------

      def self.try_optimize(v, vm, prelude, used_names, name = "")
        return nil unless v.kind == "call" && v.func && v.args

        func = v.func
        args = v.args

        # Rule 1: ecAdd(x, INFINITY) -> x, keeping ecAdd's operand gate (N-104)
        if func == "ecAdd" && args.size == 2 && infinity?(args[1], vm)
          emit_operand_gate(false, name, args[0], vm, prelude, used_names)
          return make_ref(args[0])
        end

        # Rule 2: ecAdd(INFINITY, x) -> x, keeping ecAdd's operand gate (N-104)
        if func == "ecAdd" && args.size == 2 && infinity?(args[0], vm)
          emit_operand_gate(false, name, args[1], vm, prelude, used_names)
          return make_ref(args[1])
        end

        # Rule 3: ecMul(x, 1) -> x, keeping ecMul's operand gate (N-104)
        if func == "ecMul" && args.size == 2 && const_int?(args[1], 1, vm)
          emit_operand_gate(true, name, args[0], vm, prelude, used_names)
          return make_ref(args[0])
        end

        # Rule 4: ecMul(x, 0) -> INFINITY, keeping ecMul's operand gate (N-104)
        if func == "ecMul" && args.size == 2 && const_int?(args[1], 0, vm)
          emit_operand_gate(true, name, args[0], vm, prelude, used_names)
          return make_const_hex(INFINITY_HEX)
        end

        # Rule 5: ecMulGen(0) -> INFINITY
        if func == "ecMulGen" && args.size == 1
          return make_const_hex(INFINITY_HEX) if const_int?(args[0], 0, vm)
        end

        # Rule 6: ecMulGen(1) -> G
        if func == "ecMulGen" && args.size == 1
          return make_const_hex(G_HEX) if const_int?(args[0], 1, vm)
        end

        # Rule 7: ecNegate(ecNegate(x)) -> x
        if func == "ecNegate" && args.size == 1
          inner = resolve(args[0], vm)
          # F-269 attempt 2: x is lifted out of the inner binding and
          # re-emitted here, so it must denote one value at both sites.
          if inner && inner.kind == "call" && inner.func == "ecNegate" && inner.args && inner.args.size == 1 &&
             stable?(inner.args[0], vm)
            return make_ref(inner.args[0])
          end
        end

        # Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY, keeping the adder's y = 0 abort (N-251)
        if func == "ecAdd" && args.size == 2
          neg = resolve(args[1], vm)
          if neg && neg.kind == "call" && neg.func == "ecNegate" && neg.args && neg.args.size == 1
            if same_binding?(args[0], neg.args[0], vm)
              emit_neg_cancel_gate(name, args[0], vm, prelude, used_names)
              return make_const_hex(INFINITY_HEX)
            end
          end
        end

        # Rule 8r (`ec-add-negate-cancel-reversed`): ecAdd(ecNegate(x), x) -> INFINITY
        #
        # The mirror of Rule 8. It has always been in optimizer/ec-rules.json and
        # the Go tier -- whose rule engine executes that file directly --
        # performed it; the six hand-ported tiers implemented only the forward
        # direction, so the same ANF compiled to a 1808-byte script in Go and a
        # 26140-byte one everywhere else (R-034 / CL-BUG-028).
        #
        # Placed after Rule 8 and before Rules 9/10/11 to match the JSON's rule
        # order, which is the order the Go engine tries them in.
        if func == "ecAdd" && args.size == 2
          neg = resolve(args[0], vm)
          if neg && neg.kind == "call" && neg.func == "ecNegate" && neg.args && neg.args.size == 1
            if same_binding?(args[1], neg.args[0], vm)
              # The gate reads the ecNegate operand: the name the JSON's `$x`
              # binds first, as the Go engine binds it (differs from args[1]
              # only through an alias, F-269).
              emit_neg_cancel_gate(name, neg.args[0], vm, prelude, used_names)
              return make_const_hex(INFINITY_HEX)
            end
          end
        end

        # Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
        if func == "ecMul" && args.size == 2
          inner = resolve(args[0], vm)
          k2 = get_const_int(args[1], vm)
          if inner && k2 && inner.kind == "call" && inner.func == "ecMul" && inner.args && inner.args.size == 2 &&
             stable?(inner.args[0], vm)
            k1 = get_const_int(inner.args[1], vm)
            if k1
              combined = (k1 * k2) % CURVE_N
              return make_call("ecMul", [inner.args[0], fresh_const_name(name, combined, vm, prelude, used_names)])
            end
          end
        end

        # Rule 10: ecAdd(ecMulGen(k1), ecMulGen(k2)) -> ecMulGen(k1+k2 mod N)
        if func == "ecAdd" && args.size == 2
          left_v = resolve(args[0], vm)
          right_v = resolve(args[1], vm)
          if left_v && right_v &&
             left_v.kind == "call" && left_v.func == "ecMulGen" && left_v.args && left_v.args.size == 1 &&
             right_v.kind == "call" && right_v.func == "ecMulGen" && right_v.args && right_v.args.size == 1
            k1 = get_const_int(left_v.args[0], vm)
            k2 = get_const_int(right_v.args[0], vm)
            if k1 && k2
              combined = (k1 + k2) % CURVE_N
              return make_call("ecMulGen", [fresh_const_name(name, combined, vm, prelude, used_names)])
            end
          end
        end

        # Rule 11: ecAdd(ecMul(k1,p), ecMul(k2,p)) -> ecMul(k1+k2, p) when same p
        if func == "ecAdd" && args.size == 2
          left_v = resolve(args[0], vm)
          right_v = resolve(args[1], vm)
          if left_v && right_v &&
             left_v.kind == "call" && left_v.func == "ecMul" && left_v.args && left_v.args.size == 2 &&
             right_v.kind == "call" && right_v.func == "ecMul" && right_v.args && right_v.args.size == 2
            if same_binding?(left_v.args[0], right_v.args[0], vm)
              k1 = get_const_int(left_v.args[1], vm)
              k2 = get_const_int(right_v.args[1], vm)
              if k1 && k2
                combined = (k1 + k2) % CURVE_N
                return make_call("ecMul", [left_v.args[0], fresh_const_name(name, combined, vm, prelude, used_names)])
              end
            end
          end
        end

        # Rule 12: ecMul(k, G) -> ecMulGen(k)
        if func == "ecMul" && args.size == 2
          return make_call("ecMulGen", [args[1]]) if generator?(args[0], vm)
        end

        nil
      end
      private_class_method :try_optimize

      # -----------------------------------------------------------------
      # Helpers -- value inspection
      # -----------------------------------------------------------------

      # Resolve a binding name to its ANFValue, following @ref: aliases
      # (F-269, +canonical+).
      #
      # R-263 removed a chase guarded on an impossible `load_param` shape and
      # kept this a plain lookup because the TypeScript reference was one too.
      # F-269 (user decision R77) made every tier follow aliases; they are
      # load_const values carrying the reference in `const_string`.
      def self.resolve(name, vm)
        c = canonical(name, vm)
        c.nil? ? nil : vm[c]
      end
      private_class_method :resolve

      def self.infinity?(name, vm)
        val = resolve(name, vm)
        return false unless val
        val.kind == "load_const" && val.const_string == INFINITY_HEX
      end
      private_class_method :infinity?

      def self.generator?(name, vm)
        val = resolve(name, vm)
        return false unless val
        val.kind == "load_const" && val.const_string == G_HEX
      end
      private_class_method :generator?

      def self.const_int?(name, n, vm)
        val = resolve(name, vm)
        return false unless val
        val.kind == "load_const" && val.const_big_int == n
      end
      private_class_method :const_int?

      def self.get_const_int(name, vm)
        val = resolve(name, vm)
        return nil unless val
        return val.const_big_int if val.kind == "load_const" && !val.const_big_int.nil?
        nil
      end
      private_class_method :get_const_int

      def self.same_binding?(a, b, vm)
        ca = canonical(a, vm)
        !ca.nil? && ca == canonical(b, vm)
      end
      private_class_method :same_binding?

      # F-269 attempt 2: may a name lifted out of an earlier binding be emitted
      # at the current site? Only when it denotes one value (R7, R9).
      def self.stable?(name, vm)
        !canonical(name, vm).nil?
      end
      private_class_method :stable?

      # F-269 (user decision R77): the binding +name+ ultimately names,
      # following load_const "@ref:<x>" aliases -- pass 04's
      # `const y = <expr>` and the ones R1/R2/R3/R7 leave behind (the TS
      # canonicalName in anf-ec.ts).
      #
      # nil when +name+ has no position-independent identity: ANF re-emits a
      # local's name when the source reassigns it (top level or in an if/loop
      # arm), so a REBOUND name means different values at different sites. Two
      # uses of one are not "the same $x", and nothing lifted out of an earlier
      # binding may name one (F-269 attempt 2). An alias cycle (only
      # hand-written --ir) is nil too. A hop is never taken INTO a rebound
      # name: the chain stops at the last name bound once, which is itself a
      # fixed value, and its value is the opaque alias. Matching only --
      # rewrites emit the literal names they matched.
      def self.canonical(name, vm)
        rebound = vm.respond_to?(:rebound) ? vm.rebound : Set.new
        return nil if rebound.include?(name)
        seen = Set[name]
        current = name
        loop do
          val = vm[current]
          s = val && val.kind == "load_const" ? val.const_string : nil
          return current unless s.is_a?(String) && s.length > 5 && s.start_with?("@ref:")
          nxt = s[5..]
          return current if rebound.include?(nxt)
          return nil if seen.include?(nxt)
          seen << nxt
          current = nxt
        end
      end
      private_class_method :canonical

      # -----------------------------------------------------------------
      # Helpers -- value construction
      # -----------------------------------------------------------------

      # Create a load_const that aliases another binding via @ref:.
      def self.make_ref(name)
        v = IR::ANFValue.new(kind: "load_const")
        v.const_string = "@ref:#{name}"
        v.raw_value = "@ref:#{name}"
        v
      end
      private_class_method :make_ref

      def self.make_const_hex(hex_str)
        v = IR::ANFValue.new(kind: "load_const")
        v.const_string = hex_str
        v.raw_value = hex_str
        v
      end
      private_class_method :make_const_hex

      def self.make_const_int(n)
        v = IR::ANFValue.new(kind: "load_const")
        v.const_big_int = n
        v.const_int = n
        # A folded EC scalar is a value mod n, routinely far beyond
        # Number.MAX_SAFE_INTEGER, and it now reaches the emitted IR JSON. Use
        # the tier's canonical encoding (bare number when a double carries it
        # losslessly, else the decimal digits with the JS BigInt `n` suffix, as
        # a string) rather than a bare Integer, which --emit-ir would write as
        # an unquoted 256-bit JSON number that every double-based consumer
        # silently truncates. Same encoding as
        # frontend/anf_lower.rb::_make_load_const_int.
        v.raw_value = JSON.generate(Frontend._bigint_json_value(n))
        v
      end
      private_class_method :make_const_int

      def self.make_call(func, args)
        v = IR::ANFValue.new(kind: "call")
        v.func = func
        v.args = args
        v
      end
      private_class_method :make_call

      FIELD_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

      # N-104 -- the operand gate a rewrite must leave behind. Byte-for-byte the
      # TS reference (emitAddOperandGate / emitMulOperandGate in
      # packages/runar-compiler/src/optimizer/anf-ec.ts) and the "gate" entries
      # in optimizer/ec-rules.json:
      #
      #   ecAdd: assert(ecPointX(q) < p && ecPointY(q) < p)   width (CL-BUG-095) + canonicity (R-117)
      #   ecMul: assert(q === O || ecOnCurve(q))               on-curve-or-O (R-157)
      #
      # R1-R4 replace a builtin whose first act is to validate q; without this a
      # malformed or off-curve q was accepted by the default compile and aborted
      # under disableEcOptimizer. Built only from forms no rule matches, so the
      # fixed-point loop cannot rewrite it on a later pass. Names follow the TS
      # freshName: <base><suffix>, else the first unused ..._<i>.
      def self.emit_operand_gate(of_mul, base, q, vm, prelude, used_names)
        add = lambda do |suffix, value|
          name = "#{base}#{suffix}"
          i = 1
          while used_names.include?(name)
            name = "#{base}#{suffix}_#{i}"
            i += 1
          end
          used_names << name
          vm[name] = value
          prelude << IR::ANFBinding.new(name: name, value: value)
          name
        end
        bin = lambda do |op, left, right, result_type = nil|
          IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = op
            v.left = left
            v.right = right
            v.result_type = result_type if result_type
          end
        end
        if of_mul
          inf = add.call("_inf", make_const_hex(INFINITY_HEX))
          is_inf = add.call("_isinf", bin.call("===", q, inf, "bytes"))
          on_curve = add.call("_oncurve", make_call("ecOnCurve", [q]))
          ok = add.call("_ok", bin.call("||", is_inf, on_curve))
        else
          px = add.call("_px", make_call("ecPointX", [q]))
          py = add.call("_py", make_call("ecPointY", [q]))
          fp = add.call("_fp", make_const_int(FIELD_P))
          x_ok = add.call("_pxok", bin.call("<", px, fp))
          y_ok = add.call("_pyok", bin.call("<", py, fp))
          ok = add.call("_ok", bin.call("&&", x_ok, y_ok))
        end
        add.call("_gate", Frontend._make_assert(ok))
      end
      private_class_method :emit_operand_gate

      # N-251 -- the gate R8/R8r (ecAdd(q, ecNegate(q)) -> O and its mirror)
      # must leave behind (user decision R96). Byte-for-byte the TS reference
      # (emitNegCancelGate in packages/runar-compiler/src/optimizer/anf-ec.ts):
      #
      #   assert(ecPointX(q) === 0 || ecPointY(q) !== 0)
      #
      # The replaced ecAdd doubles exactly when y(q) = 0, and N-110 made the
      # adder abort on a doubling with px != 0 and py == 0; the px == 0 term
      # keeps O + O = O. Width and canonicity are checked by the inner
      # ecNegate(q) call, which is never dead-code-eliminated. Names as in
      # emit_operand_gate.
      def self.emit_neg_cancel_gate(base, q, vm, prelude, used_names)
        add = lambda do |suffix, value|
          name = "#{base}#{suffix}"
          i = 1
          while used_names.include?(name)
            name = "#{base}#{suffix}_#{i}"
            i += 1
          end
          used_names << name
          vm[name] = value
          prelude << IR::ANFBinding.new(name: name, value: value)
          name
        end
        bin = lambda do |op, left, right|
          IR::ANFValue.new(kind: "bin_op").tap do |v|
            v.op = op
            v.left = left
            v.right = right
          end
        end
        px = add.call("_px", make_call("ecPointX", [q]))
        py = add.call("_py", make_call("ecPointY", [q]))
        zero = add.call("_zero", make_const_int(0))
        x_zero = add.call("_pxz", bin.call("===", px, zero))
        y_non_zero = add.call("_pynz", bin.call("!==", py, zero))
        ok = add.call("_ok", bin.call("||", x_zero, y_non_zero))
        add.call("_gate", Frontend._make_assert(ok))
      end
      private_class_method :emit_neg_cancel_gate

      # Bind a freshly folded constant and return its name.
      #
      # This is needed when optimization produces a new constant (e.g. k1*k2)
      # that needs to be referenced by name in a call.
      #
      # The binding is appended to +prelude+ -- the rebuilt method body, at the
      # point just before the binding currently being rewritten -- as well as
      # registered in the value map. Registering it in the value map alone is
      # not enough: stack lowering walks the body, so a call referencing a name
      # that never got a binding dies with
      # <tt>value "<name>" not found on stack</tt>. Mirrors
      # AnfOptimize.freshConstName (Java), buildOpHelper (Go) and the
      # +newBindings+ list in anf-ec.ts (TypeScript).
      #
      # The name follows the TS +freshName(`${binding.name}_k`, usedNames)+:
      # +<base>_k+, else the first unused +<base>_k_<i>+ (F-086: against every
      # name the method already uses, see collect_used_names), and is reserved
      # there. N-112: it is derived from the program alone -- no class-level
      # counter -- so the same program always gets the same names.
      def self.fresh_const_name(base, value, vm, prelude, used_names)
        stem = "#{base}_k"
        name = stem
        i = 1
        while used_names.include?(name)
          name = "#{stem}_#{i}"
          i += 1
        end
        used_names << name
        const = make_const_int(value)
        vm[name] = const
        prelude << IR::ANFBinding.new(name: name, value: const)
        name
      end
      private_class_method :fresh_const_name

      # -----------------------------------------------------------------
      # Dead binding elimination
      # -----------------------------------------------------------------
      #
      # The DCE pass lives in its own discrete module now
      # (frontend/dce.rb). The thin delegates below keep the existing
      # ANFOptimize-private API working for in-tree tests; new callers
      # should go through RunarCompiler::Frontend::DCE directly.
      def self.eliminate_dead_bindings(method)
        RunarCompiler::Frontend::DCE.eliminate_dead_bindings(method)
      end
      private_class_method :eliminate_dead_bindings

      def self.collect_refs(v, used)
        RunarCompiler::Frontend::DCE.collect_refs(v, used)
      end
      private_class_method :collect_refs

      def self.has_side_effect?(v)
        RunarCompiler::Frontend::DCE.has_side_effect?(v)
      end
      private_class_method :has_side_effect?
    end
  end
end
