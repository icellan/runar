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

      # Counter for generating fresh constant binding names
      @fresh_counter = 0

      class << self
        # @return [Integer]
        attr_accessor :fresh_counter
      end

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

        result = deep_copy_program(program)
        result.methods.each { |m| optimize_method(m) }
        result
      end

      # -----------------------------------------------------------------
      # Deep copy helpers
      # -----------------------------------------------------------------

      def self.deep_copy_program(program)
        IR::ANFProgram.new(
          contract_name: program.contract_name,
          properties: program.properties.map(&:dup),
          methods: program.methods.map { |m| deep_copy_method(m) }
        )
      end
      private_class_method :deep_copy_program

      def self.deep_copy_method(method)
        IR::ANFMethod.new(
          name: method.name,
          params: method.params.map(&:dup),
          body: method.body.map { |b| deep_copy_binding(b) },
          is_public: method.is_public
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

      def self.deep_copy_value(v)
        nv = IR::ANFValue.new(kind: v.kind)
        nv.name         = v.name
        nv.raw_value    = v.raw_value
        nv.const_string = v.const_string
        nv.const_big_int = v.const_big_int
        nv.const_bool   = v.const_bool
        nv.const_int    = v.const_int
        nv.op           = v.op
        nv.left         = v.left
        nv.right        = v.right
        nv.result_type  = v.result_type
        nv.operand      = v.operand
        nv.func         = v.func
        nv.args         = v.args&.dup
        nv.object       = v.object
        nv.method       = v.method
        nv.cond         = v.cond
        nv.count        = v.count
        nv.iter_var     = v.iter_var
        nv.value_ref    = v.value_ref
        nv.preimage     = v.preimage
        nv.satoshis     = v.satoshis
        nv.state_values = v.state_values&.dup
        nv.script_bytes = v.script_bytes
        nv.elements     = v.elements&.dup
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

      def self.optimize_method(method)
        value_map = {}
        changed = true
        while changed
          changed = false
          new_body = []
          method.body.each do |binding|
            optimized = try_optimize(binding.value, value_map)
            if optimized
              binding = IR::ANFBinding.new(
                name: binding.name,
                value: optimized,
                source_loc: binding.source_loc
              )
              changed = true
            end
            value_map[binding.name] = binding.value
            new_body << binding
          end
          method.body = new_body
        end

        # Dead binding elimination
        eliminate_dead_bindings(method)
      end
      private_class_method :optimize_method

      # -----------------------------------------------------------------
      # Optimization rules
      # -----------------------------------------------------------------

      def self.try_optimize(v, vm)
        return nil unless v.kind == "call" && v.func && v.args

        func = v.func
        args = v.args

        # Rule 1: ecAdd(x, INFINITY) -> x
        if func == "ecAdd" && args.size == 2
          return make_ref(args[0]) if infinity?(args[1], vm)
        end

        # Rule 2: ecAdd(INFINITY, x) -> x
        if func == "ecAdd" && args.size == 2
          return make_ref(args[1]) if infinity?(args[0], vm)
        end

        # Rule 3: ecMul(x, 1) -> x
        if func == "ecMul" && args.size == 2
          return make_ref(args[0]) if const_int?(args[1], 1, vm)
        end

        # Rule 4: ecMul(x, 0) -> INFINITY
        if func == "ecMul" && args.size == 2
          return make_const_hex(INFINITY_HEX) if const_int?(args[1], 0, vm)
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
          if inner && inner.kind == "call" && inner.func == "ecNegate" && inner.args && inner.args.size == 1
            return make_ref(inner.args[0])
          end
        end

        # Rule 8: ecAdd(x, ecNegate(x)) -> INFINITY
        if func == "ecAdd" && args.size == 2
          neg = resolve(args[1], vm)
          if neg && neg.kind == "call" && neg.func == "ecNegate" && neg.args && neg.args.size == 1
            return make_const_hex(INFINITY_HEX) if same_binding?(args[0], neg.args[0], vm)
          end
        end

        # Rule 9: ecMul(ecMul(p, k1), k2) -> ecMul(p, k1*k2 mod N)
        if func == "ecMul" && args.size == 2
          inner = resolve(args[0], vm)
          k2 = get_const_int(args[1], vm)
          if inner && k2 && inner.kind == "call" && inner.func == "ecMul" && inner.args && inner.args.size == 2
            k1 = get_const_int(inner.args[1], vm)
            if k1
              combined = (k1 * k2) % CURVE_N
              return make_call("ecMul", [inner.args[0], fresh_const_name(combined, vm)])
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
              return make_call("ecMulGen", [fresh_const_name(combined, vm)])
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
                return make_call("ecMul", [left_v.args[0], fresh_const_name(combined, vm)])
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

      # Resolve a binding name to its ANFValue, following @ref: aliases.
      def self.resolve(name, vm)
        seen = Set.new
        current = name
        while vm.key?(current)
          break if seen.include?(current)
          seen.add(current)
          val = vm[current]
          if val.kind == "load_param" && val.name && val.name.start_with?("@ref:")
            current = val.name[5..]
            next
          end
          return val
        end
        vm[current]
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
        canonical(a, vm) == canonical(b, vm)
      end
      private_class_method :same_binding?

      # Follow @ref: chains to get the canonical binding name.
      def self.canonical(name, vm)
        seen = Set.new
        current = name
        while vm.key?(current)
          break if seen.include?(current)
          seen.add(current)
          val = vm[current]
          if val.kind == "load_param" && val.name && val.name.start_with?("@ref:")
            current = val.name[5..]
            next
          end
          break
        end
        current
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
        v.raw_value = n
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

      # Insert a fresh constant binding into the value map and return its name.
      #
      # This is needed when optimization produces a new constant (e.g. k1*k2)
      # that needs to be referenced by name in a call.
      def self.fresh_const_name(value, vm)
        self.fresh_counter += 1
        name = "__ec_opt_#{fresh_counter}"
        vm[name] = make_const_int(value)
        name
      end
      private_class_method :fresh_const_name

      # -----------------------------------------------------------------
      # Dead binding elimination
      # -----------------------------------------------------------------

      SIDE_EFFECT_KINDS = %w[
        assert update_prop check_preimage deserialize_state
        add_output add_raw_output add_data_output
        if loop call method_call
      ].to_set.freeze

      # Remove bindings whose results are never referenced.
      #
      # Uses iterative elimination to handle transitive dead code
      # (e.g., if A references B and A is dead, B may also become dead).
      def self.eliminate_dead_bindings(method)
        current = method.body
        changed = true

        while changed
          changed = false
          used = Set.new
          current.each { |binding| collect_refs(binding.value, used) }

          filtered = []
          current.each do |binding|
            if used.include?(binding.name) || has_side_effect?(binding.value)
              filtered << binding
            else
              changed = true
            end
          end

          current = filtered
        end

        method.body = current
      end
      private_class_method :eliminate_dead_bindings

      # Walk an ANFValue and collect all binding name references.
      def self.collect_refs(v, used)
        if v.kind == "load_param"
          return
        end

        if v.kind == "load_const"
          if v.const_string && v.const_string.start_with?("@ref:")
            used.add(v.const_string[5..])
          end
          return
        end

        return if v.kind == "load_prop" || v.kind == "get_state_script"

        used.add(v.left)        if v.left
        used.add(v.right)       if v.right
        used.add(v.operand)     if v.operand
        used.add(v.cond)        if v.cond
        used.add(v.value_ref)   if v.value_ref
        used.add(v.object)      if v.object
        used.add(v.satoshis)    if v.satoshis
        used.add(v.script_bytes) if v.script_bytes
        used.add(v.preimage)    if v.preimage
        v.args&.each         { |a| used.add(a) }
        v.state_values&.each { |sv| used.add(sv) }
        v.then&.each  { |b| collect_refs(b.value, used) }
        v.else_&.each { |b| collect_refs(b.value, used) }
        v.body&.each  { |b| collect_refs(b.value, used) }
      end
      private_class_method :collect_refs

      def self.has_side_effect?(v)
        SIDE_EFFECT_KINDS.include?(v.kind)
      end
      private_class_method :has_side_effect?
    end
  end
end
