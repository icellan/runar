# frozen_string_literal: true

# Baby Bear field arithmetic codegen -- Baby Bear prime field operations
# for Bitcoin Script.
#
# Follows the ec.rb pattern: self-contained module imported by stack.rb.
# Uses a BBTracker for named stack state tracking.
#
# Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
# Used by SP1 STARK proofs (FRI verification).
#
# All values fit in a single BSV script number (31-bit prime).
# No multi-limb arithmetic needed.
#
# Direct port of packages/runar-compiler/src/passes/babybear-codegen.ts

module RunarCompiler
  module Codegen
    module BabyBear
      # =================================================================
      # Constants
      # =================================================================

      # Baby Bear field prime p = 2^31 - 2^27 + 1
      BB_P = 2013265921

      # p - 2, used for Fermat's little theorem modular inverse
      BB_P_MINUS_2 = BB_P - 2

      # =================================================================
      # StackOp / PushValue helpers (same pattern as EC module)
      # =================================================================

      # Build a StackOp hash.
      #
      # @param op [String] operation type
      # @param kwargs [Hash] additional fields
      # @return [Hash] StackOp hash
      def self.make_stack_op(op:, **kwargs)
        result = { op: op }
        kwargs.each { |k, v| result[k] = v }
        result
      end

      # Build a PushValue hash for a big integer.
      #
      # @param n [Integer]
      # @return [Hash] PushValue hash
      def self.big_int_push(n)
        { kind: "bigint", big_int: n }
      end

      # =================================================================
      # BBTracker -- named stack state tracker (mirrors ECTracker)
      # =================================================================

      class BBTracker
        # @return [Array<String, nil>] named stack entries
        attr_accessor :nm

        # @param init [Array<String>] initial stack names
        # @param emit [Proc] callback receiving a StackOp hash
        def initialize(init, emit)
          @nm = init.dup
          @e = emit
        end

        # @return [Integer] current stack depth
        def depth
          @nm.length
        end

        # Find the depth (distance from top) of a named stack entry.
        #
        # @param name [String]
        # @return [Integer]
        def find_depth(name)
          i = @nm.length - 1
          while i >= 0
            return @nm.length - 1 - i if @nm[i] == name
            i -= 1
          end
          raise "BBTracker: '#{name}' not on stack #{@nm}"
        end

        # Push a big integer onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_int(n, v)
          @e.call(BabyBear.make_stack_op(op: "push", value: BabyBear.big_int_push(v)))
          @nm.push(n)
        end

        # Duplicate top of stack.
        #
        # @param n [String] name for the duplicate
        def dup(n)
          @e.call(BabyBear.make_stack_op(op: "dup"))
          @nm.push(n)
        end

        # Drop top of stack.
        def drop
          @e.call(BabyBear.make_stack_op(op: "drop"))
          @nm.pop if @nm.length > 0
        end

        # Remove second-to-top stack element.
        def nip
          @e.call(BabyBear.make_stack_op(op: "nip"))
          l = @nm.length
          if l >= 2
            @nm[l - 2..l - 1] = [@nm[l - 1]]
          end
        end

        # Copy second-to-top onto top.
        #
        # @param n [String] name for the copy
        def over(n)
          @e.call(BabyBear.make_stack_op(op: "over"))
          @nm.push(n)
        end

        # Swap top two stack elements.
        def swap
          @e.call(BabyBear.make_stack_op(op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
          end
        end

        # Rotate top three stack elements.
        def rot
          @e.call(BabyBear.make_stack_op(op: "rot"))
          l = @nm.length
          if l >= 3
            r = @nm[l - 3]
            @nm.delete_at(l - 3)
            @nm.push(r)
          end
        end

        # Pick (copy) an item from depth d to top.
        #
        # @param n [String] name for the copy
        # @param d [Integer] depth
        def pick(n, d)
          @e.call(BabyBear.make_stack_op(op: "pick", depth: d))
          @nm.push(n)
        end

        # Roll an item from depth d to top.
        #
        # @param d [Integer] depth
        def roll(d)
          @e.call(BabyBear.make_stack_op(op: "roll", depth: d))
          idx = @nm.length - 1 - d
          item = @nm.delete_at(idx)
          @nm.push(item)
        end

        # Bring a named value to stack top (non-consuming copy via PICK).
        #
        # @param name [String] source name
        # @param new_name [String] name for the copy
        def copy_to_top(name, new_name)
          d = find_depth(name)
          if d == 0
            dup(new_name)
          else
            pick(new_name, d)
          end
        end

        # Bring a named value to stack top (consuming via ROLL).
        #
        # @param name [String]
        def to_top(name)
          d = find_depth(name)
          return if d == 0
          roll(d)
        end

        # Rename the top-of-stack entry.
        #
        # @param new_name [String]
        def rename(new_name)
          @nm[@nm.length - 1] = new_name
        end

        # Emit raw opcodes; tracker adjusts the name stack.
        #
        # @param consume [Array<String>] names consumed from the stack
        # @param produce [String, nil] name produced (nil means no output pushed)
        # @param fn [Proc] block receiving an emit callback
        def raw_block(consume, produce, &fn)
          fn.call(@e)
          consume.length.times { @nm.pop }
          @nm.push(produce) unless produce.nil?
        end
      end

      # =================================================================
      # Field arithmetic internals
      # =================================================================

      # fieldMod: ensure value is in [0, p).
      # Pattern: (a % p + p) % p -- handles negative values from sub.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bb_field_mod(t, a_name, result_name)
        t.to_top(a_name)
        t.raw_block([a_name], result_name) do |e|
          # (a % p + p) % p
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # fieldAdd: (a + b) mod p.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bb_field_add(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_bb_add") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        end
        # Sum of two values in [0, p-1] is always non-negative, simple OP_MOD
        t.to_top("_bb_add")
        t.raw_block(["_bb_add"], result_name) do |e|
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # fieldSub: (a - b) mod p (non-negative).
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bb_field_sub(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_bb_diff") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        end
        # Difference can be negative, need full mod-reduce
        bb_field_mod(t, "_bb_diff", result_name)
      end

      # fieldMul: (a * b) mod p.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bb_field_mul(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_bb_prod") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
        end
        # Product of two non-negative values is non-negative, simple OP_MOD
        t.to_top("_bb_prod")
        t.raw_block(["_bb_prod"], result_name) do |e|
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # fieldSqr: (a * a) mod p.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bb_field_sqr(t, a_name, result_name)
        t.copy_to_top(a_name, "_bb_sqr_copy")
        bb_field_mul(t, a_name, "_bb_sqr_copy", result_name)
      end

      # fieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
      # p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
      # 31 bits, popcount 28.
      # ~30 squarings + ~27 multiplies = ~57 compound operations.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bb_field_inv(t, a_name, result_name)
        # Start: result = a (for MSB bit 30 = 1)
        t.copy_to_top(a_name, "_inv_r")

        # Process bits 29 down to 0 (30 bits)
        p_minus_2 = BB_P_MINUS_2
        29.downto(0) do |i|
          # Always square
          bb_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")

          # Multiply if bit is set
          if (p_minus_2 >> i) & 1 == 1
            t.copy_to_top(a_name, "_inv_a")
            bb_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")
          end
        end

        # Clean up original input and rename result
        t.to_top(a_name)
        t.drop
        t.to_top("_inv_r")
        t.rename(result_name)
      end

      # =================================================================
      # Public emit functions -- entry points called from stack.rb
      # =================================================================

      # Baby Bear field addition.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a + b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_add(emit)
        t = BBTracker.new(["a", "b"], emit)
        bb_field_add(t, "a", "b", "result")
        # Stack should now be: [result]
      end

      # Baby Bear field subtraction.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a - b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_sub(emit)
        t = BBTracker.new(["a", "b"], emit)
        bb_field_sub(t, "a", "b", "result")
      end

      # Baby Bear field multiplication.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a * b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_mul(emit)
        t = BBTracker.new(["a", "b"], emit)
        bb_field_mul(t, "a", "b", "result")
      end

      # Baby Bear field multiplicative inverse.
      # Stack in: [..., a]
      # Stack out: [..., a^(p-2) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_inv(emit)
        t = BBTracker.new(["a"], emit)
        bb_field_inv(t, "a", "result")
      end

      # =================================================================
      # Dispatch
      # =================================================================

      BB_DISPATCH = {
        "bbFieldAdd" => method(:emit_bb_field_add),
        "bbFieldSub" => method(:emit_bb_field_sub),
        "bbFieldMul" => method(:emit_bb_field_mul),
        "bbFieldInv" => method(:emit_bb_field_inv),
      }.freeze

      # BB builtin function names.
      BB_BUILTIN_NAMES = Set.new(%w[
        bbFieldAdd bbFieldSub bbFieldMul bbFieldInv
      ]).freeze

      # Return true if +name+ is a Baby Bear builtin.
      #
      # @param name [String]
      # @return [Boolean]
      def self.bb_builtin?(name)
        BB_BUILTIN_NAMES.include?(name)
      end

      # Call the appropriate BB emit function for func_name.
      #
      # @param func_name [String]
      # @param emit [Proc] callback receiving a StackOp hash
      # @raise [RuntimeError] if func_name is not a known BB builtin
      def self.dispatch_bb_builtin(func_name, emit)
        fn = BB_DISPATCH[func_name]
        raise "unknown Baby Bear builtin: #{func_name}" if fn.nil?
        fn.call(emit)
      end
    end
  end
end
