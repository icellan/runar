# frozen_string_literal: true

# Constant folding pass for ANF IR.
#
# Evaluates compile-time-known expressions and replaces them with +load_const+
# bindings.  Constants are propagated through the binding chain so downstream
# operations can be folded too.
#
# Direct port of compilers/python/runar_compiler/frontend/constant_fold.py.

require "json"
require_relative "../ir/types"

module RunarCompiler
  module Frontend
    module ConstantFold
      # -----------------------------------------------------------------
      # Constant environment
      # -----------------------------------------------------------------
      #
      # Constants are represented as [type_tag, value] pairs:
      #   ["int", int_value]
      #   ["bool", bool_value]
      #   ["str", str_value]

      # -----------------------------------------------------------------
      # Binary operation evaluation
      # -----------------------------------------------------------------

      # @param op    [String]
      # @param left  [Array(String, Object)]
      # @param right [Array(String, Object)]
      # @return [Array(String, Object), nil]
      def self.eval_bin_op(op, left, right)
        # Arithmetic/bitwise/comparison on ints
        if left[0] == "int" && right[0] == "int"
          a = left[1]
          b = right[1]
          case op
          when "+"  then return ["int", a + b]
          when "-"  then return ["int", a - b]
          when "*"  then return ["int", a * b]
          when "/"
            return nil if b == 0
            # Truncated division (toward zero), matching JS BigInt semantics
            return ["int", _trunc_div(a, b)]
          when "%"
            return nil if b == 0
            # Remainder matching JS BigInt (sign follows dividend)
            return ["int", a - _trunc_div(a, b) * b]
          when "===" then return ["bool", a == b]
          when "!==" then return ["bool", a != b]
          when "<"   then return ["bool", a < b]
          when ">"   then return ["bool", a > b]
          when "<="  then return ["bool", a <= b]
          when ">="  then return ["bool", a >= b]
          when "&"   then return ["int", a & b]
          when "|"   then return ["int", a | b]
          when "^"   then return ["int", a ^ b]
          when "<<"
            return nil if a < 0   # skip for negative left operand (BSV shifts are logical)
            return nil if b < 0 || b > 128
            return ["int", a << b]
          when ">>"
            return nil if a < 0   # skip for negative left operand (BSV shifts are logical)
            return nil if b < 0 || b > 128
            return ["int", a >> b]
          else
            return nil
          end
        end

        # Boolean operations
        if left[0] == "bool" && right[0] == "bool"
          a_b = left[1]
          b_b = right[1]
          case op
          when "&&"  then return ["bool", a_b && b_b]
          when "||"  then return ["bool", a_b || b_b]
          when "===" then return ["bool", a_b == b_b]
          when "!==" then return ["bool", a_b != b_b]
          else
            return nil
          end
        end

        # String (ByteString) operations
        if left[0] == "str" && right[0] == "str"
          a_s = left[1]
          b_s = right[1]
          case op
          when "+"
            return nil unless valid_hex?(a_s) && valid_hex?(b_s)
            return ["str", a_s + b_s]
          when "===" then return ["bool", a_s == b_s]
          when "!==" then return ["bool", a_s != b_s]
          else
            return nil
          end
        end

        # Cross-type equality
        return ["bool", false] if op == "==="
        return ["bool", true]  if op == "!=="

        nil
      end
      private_class_method :eval_bin_op

      # Truncated division toward zero (matching JS BigInt semantics).
      def self._trunc_div(a, b)
        q = a.abs / b.abs
        q = -q if (a < 0) ^ (b < 0)
        q
      end
      private_class_method :_trunc_div

      def self.valid_hex?(s)
        /\A[0-9a-fA-F]*\z/.match?(s)
      end
      private_class_method :valid_hex?

      # -----------------------------------------------------------------
      # Unary operation evaluation
      # -----------------------------------------------------------------

      def self.eval_unary_op(op, operand)
        if operand[0] == "bool"
          return ["bool", !operand[1]] if op == "!"
          return nil
        end

        if operand[0] == "int"
          n = operand[1]
          case op
          when "-" then return ["int", -n]
          when "~" then return ["int", ~n]
          when "!" then return ["bool", n == 0]
          else
            return nil
          end
        end

        nil
      end
      private_class_method :eval_unary_op

      # -----------------------------------------------------------------
      # Builtin call evaluation (pure math functions only)
      # -----------------------------------------------------------------

      def self.eval_builtin_call(func_name, const_args)
        int_args = []
        const_args.each do |a|
          return nil unless a[0] == "int"
          int_args << a[1]
        end

        case func_name
        when "abs"
          return nil unless int_args.size == 1
          return ["int", int_args[0].abs]

        when "min"
          return nil unless int_args.size == 2
          return ["int", [int_args[0], int_args[1]].min]

        when "max"
          return nil unless int_args.size == 2
          return ["int", [int_args[0], int_args[1]].max]

        when "safediv"
          return nil unless int_args.size == 2 && int_args[1] != 0
          return ["int", _trunc_div(int_args[0], int_args[1])]

        when "safemod"
          return nil unless int_args.size == 2 && int_args[1] != 0
          a, b = int_args[0], int_args[1]
          return ["int", a - _trunc_div(a, b) * b]

        when "clamp"
          return nil unless int_args.size == 3
          val, lo, hi = int_args[0], int_args[1], int_args[2]
          return ["int", [lo, [val, hi].min].max]

        when "sign"
          return nil unless int_args.size == 1
          n = int_args[0]
          if n > 0
            return ["int", 1]
          elsif n < 0
            return ["int", -1]
          else
            return ["int", 0]
          end

        when "pow"
          return nil unless int_args.size == 2
          base, exp = int_args[0], int_args[1]
          return nil if exp < 0 || exp > 256
          result = 1
          exp.times { result *= base }
          return ["int", result]

        when "mulDiv"
          return nil unless int_args.size == 3 && int_args[2] != 0
          tmp = int_args[0] * int_args[1]
          return ["int", _trunc_div(tmp, int_args[2])]

        when "percentOf"
          return nil unless int_args.size == 2
          tmp = int_args[0] * int_args[1]
          return ["int", _trunc_div(tmp, 10_000)]

        when "sqrt"
          return nil unless int_args.size == 1
          n = int_args[0]
          return nil if n < 0
          return ["int", 0] if n == 0
          # Integer square root via Newton's method
          x = n
          y = (x + 1) / 2
          while y < x
            x = y
            y = (x + n / x) / 2
          end
          return ["int", x]

        when "gcd"
          return nil unless int_args.size == 2
          a, b = int_args[0].abs, int_args[1].abs
          a, b = b, a % b while b != 0
          return ["int", a]

        when "divmod"
          return nil unless int_args.size == 2 && int_args[1] != 0
          return ["int", _trunc_div(int_args[0], int_args[1])]

        when "log2"
          return nil unless int_args.size == 1
          n = int_args[0]
          return ["int", 0] if n <= 0
          return ["int", n.bit_length - 1]

        when "bool"
          return nil unless int_args.size == 1
          return ["bool", int_args[0] != 0]
        end

        nil
      end
      private_class_method :eval_builtin_call

      # -----------------------------------------------------------------
      # ANF Value <-> ConstValue conversion
      # -----------------------------------------------------------------

      # Extract a constant value from a load_const ANFValue.
      # @return [Array(String, Object), nil]
      def self.anf_value_to_const(value)
        return nil unless value.kind == "load_const"

        # Skip @ref: aliases -- they are binding references, not real constants
        if value.const_string && value.const_string.start_with?("@ref:")
          return nil
        end

        # Check bool BEFORE int
        unless value.const_bool.nil?
          return ["bool", value.const_bool]
        end
        unless value.const_big_int.nil?
          return ["int", value.const_big_int]
        end
        unless value.const_int.nil?
          return ["int", value.const_int]
        end
        unless value.const_string.nil?
          return ["str", value.const_string]
        end

        # Try to decode from raw_value
        raw = value.raw_value
        return nil if raw.nil?

        case raw
        when true, false
          return ["bool", raw]
        when Integer
          return ["int", raw]
        when Float
          return ["int", raw.to_i]
        when String
          return nil if raw.start_with?("@ref:")
          return ["str", raw]
        end

        nil
      end
      private_class_method :anf_value_to_const

      # Convert a ConstValue to a load_const ANFValue.
      def self.const_to_anf_value(cv)
        tag, val = cv
        v = IR::ANFValue.new(kind: "load_const")
        v.raw_value = JSON.generate(val)

        case tag
        when "int"
          v.const_big_int = val
          v.const_int = val
        when "bool"
          v.const_bool = val
        when "str"
          v.const_string = val
        end

        v
      end
      private_class_method :const_to_anf_value

      # -----------------------------------------------------------------
      # Fold bindings
      # -----------------------------------------------------------------

      def self.fold_bindings(bindings, env)
        bindings.map { |b| fold_binding(b, env) }
      end
      private_class_method :fold_bindings

      def self.fold_binding(binding, env)
        folded_value = fold_value(binding.value, env)

        # If the folded value is a load_const, register in the environment
        cv = anf_value_to_const(folded_value)
        env[binding.name] = cv unless cv.nil?

        IR::ANFBinding.new(
          name: binding.name,
          value: folded_value,
          source_loc: binding.source_loc
        )
      end
      private_class_method :fold_binding

      # -----------------------------------------------------------------
      # Fold a single value
      # -----------------------------------------------------------------

      # Kinds that fall through fold_value unchanged. Listing them
      # explicitly lets us raise UnknownANFKindError on any kind that
      # isn't a known fold case, so a forgotten dispatch-site update fails
      # loudly instead of silently corrupting downstream passes.
      FOLD_VALUE_PASSTHROUGH_KINDS = %w[
        assert
        update_prop
        check_preimage
        deserialize_state
        add_output
        add_raw_output
        add_data_output
        array_literal
        get_state_script
      ].freeze

      def self.fold_value(value, env)
        kind = value.kind

        return value if kind == "load_const" || kind == "load_param" || kind == "load_prop"

        if kind == "bin_op"
          left_const = env[value.left]
          right_const = env[value.right]
          if left_const && right_const
            result = eval_bin_op(value.op, left_const, right_const)
            return const_to_anf_value(result) if result
          end
          return value
        end

        if kind == "unary_op"
          operand_const = env[value.operand]
          if operand_const
            result = eval_unary_op(value.op, operand_const)
            return const_to_anf_value(result) if result
          end
          return value
        end

        if kind == "call"
          if value.args && value.args.all? { |a| env.key?(a) }
            const_args = value.args.map { |a| env[a] }
            folded = eval_builtin_call(value.func, const_args)
            return const_to_anf_value(folded) if folded
          end
          return value
        end

        return value if kind == "method_call"

        if kind == "if"
          cond_const = env[value.cond]
          if cond_const && cond_const[0] == "bool"
            cond_val = cond_const[1]
            if cond_val
              then_env = env.dup
              folded_then = fold_bindings(value.then || [], then_env)
              # Merge constants from taken branch back into env
              folded_then.each do |b|
                cv = anf_value_to_const(b.value)
                env[b.name] = cv unless cv.nil?
              end
              new_v = IR::ANFValue.new(kind: "if")
              new_v.cond = value.cond
              new_v.then = folded_then
              new_v.else_ = []
              return new_v
            else
              else_env = env.dup
              folded_else = fold_bindings(value.else_ || [], else_env)
              folded_else.each do |b|
                cv = anf_value_to_const(b.value)
                env[b.name] = cv unless cv.nil?
              end
              new_v = IR::ANFValue.new(kind: "if")
              new_v.cond = value.cond
              new_v.then = []
              new_v.else_ = folded_else
              return new_v
            end
          else
            # Condition not known -- fold both branches independently
            then_env = env.dup
            else_env = env.dup
            folded_then = fold_bindings(value.then || [], then_env)
            folded_else = fold_bindings(value.else_ || [], else_env)
            new_v = IR::ANFValue.new(kind: "if")
            new_v.cond = value.cond
            new_v.then = folded_then
            new_v.else_ = folded_else
            return new_v
          end
        end

        if kind == "loop"
          body_env = env.dup
          folded_body = fold_bindings(value.body || [], body_env)
          new_v = IR::ANFValue.new(kind: "loop")
          new_v.count = value.count
          new_v.body = folded_body
          new_v.iter_var = value.iter_var
          return new_v
        end

        if kind == "raw_script"
          # Opaque byte span -- never folded. Bytes are byte-canonical and
          # the peephole optimizer treats it as a hard barrier.
          return value
        end

        # Terminal / side-effecting kinds pass through.  Anything not in
        # the explicit allowlist is a forgotten dispatch-site update:
        # fail loudly so the regression is caught at the first binding
        # instead of leaking an unhandled variant into Stack IR / hex.
        return value if FOLD_VALUE_PASSTHROUGH_KINDS.include?(kind)

        raise ::RunarCompiler::IR::UnknownANFKindError.new(kind, "constant-fold.foldValue")
      end
      private_class_method :fold_value

      # -----------------------------------------------------------------
      # Side-effect detection
      # -----------------------------------------------------------------

      SIDE_EFFECT_KINDS = %w[
        assert update_prop check_preimage deserialize_state
        add_output add_raw_output add_data_output
        if loop call method_call raw_script
      ].freeze

      # Kinds known to have no observable side effects.  Listed explicitly
      # so an unknown kind raises UnknownANFKindError instead of silently
      # being treated as side-effect-free (which would cause DCE to drop
      # a new side-effecting variant).
      SIDE_EFFECT_FREE_KINDS = %w[
        load_param load_prop load_const get_state_script
        bin_op unary_op array_literal
      ].freeze

      # Return true if this value kind has observable side effects.
      def self.has_side_effect(value)
        kind = value.kind
        return true  if SIDE_EFFECT_KINDS.include?(kind)
        return false if SIDE_EFFECT_FREE_KINDS.include?(kind)

        raise ::RunarCompiler::IR::UnknownANFKindError.new(kind, "constant-fold.hasSideEffect")
      end

      # -----------------------------------------------------------------
      # Reference collection
      # -----------------------------------------------------------------

      # Walk an ANFValue and collect all binding name references.
      #
      # Uses an explicit kind dispatch so an unknown variant raises
      # UnknownANFKindError instead of silently contributing zero refs
      # (which would cause DCE to drop a live binding).
      def self.collect_refs_from_value(value, used)
        case value.kind
        when "load_param", "load_prop", "get_state_script"
          # No refs.
        when "load_const"
          if value.const_string && value.const_string.start_with?("@ref:")
            used.add(value.const_string[5..])
          end
        when "bin_op"
          used.add(value.left)  if value.left
          used.add(value.right) if value.right
        when "unary_op"
          used.add(value.operand) if value.operand
        when "call"
          value.args&.each { |a| used.add(a) }
        when "method_call"
          used.add(value.object) if value.object
          value.args&.each { |a| used.add(a) }
        when "if"
          used.add(value.cond) if value.cond
          value.then&.each  { |b| collect_refs_from_value(b.value, used) }
          value.else_&.each { |b| collect_refs_from_value(b.value, used) }
        when "loop"
          value.body&.each { |b| collect_refs_from_value(b.value, used) }
        when "assert", "update_prop"
          used.add(value.value_ref) if value.value_ref
        when "check_preimage", "deserialize_state"
          used.add(value.preimage) if value.preimage
        when "add_output"
          used.add(value.satoshis) if value.satoshis
          value.state_values&.each { |sv| used.add(sv) }
          used.add(value.preimage) if value.preimage
        when "add_raw_output", "add_data_output"
          used.add(value.satoshis)     if value.satoshis
          used.add(value.script_bytes) if value.script_bytes
        when "array_literal"
          value.elements&.each { |e| used.add(e) }
        when "raw_script"
          # Opaque: no SSA operand refs.
        else
          # Exhaustiveness guard.  A silent no-op would let DCE drop a
          # live binding because its refs go uncollected.
          raise ::RunarCompiler::IR::UnknownANFKindError.new(value.kind, "constant-fold.collectRefsFromValue")
        end
      end

      # -----------------------------------------------------------------
      # Public API
      # -----------------------------------------------------------------

      def self.fold_method(method)
        env = {}
        folded_body = fold_bindings(method.body, env)
        IR::ANFMethod.new(
          name: method.name,
          params: method.params.dup,
          body: folded_body,
          is_public: method.is_public
        )
      end
      private_class_method :fold_method

      # Apply constant folding to an ANF program.
      #
      # Evaluates compile-time-known expressions and replaces them with
      # +load_const+ bindings.  Does NOT run dead binding elimination --
      # that is handled separately by the EC optimizer's DCE pass.
      #
      # @param program [IR::ANFProgram]
      # @return [IR::ANFProgram]
      def self.fold_constants(program)
        IR::ANFProgram.new(
          contract_name: program.contract_name,
          properties: program.properties.dup,
          methods: program.methods.map { |m| fold_method(m) }
        )
      end
    end
  end
end
