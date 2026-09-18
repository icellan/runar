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
          if d == 0
            dup(n)
            return
          end
          if d == 1
            over(n)
            return
          end
          @e.call(BabyBear.make_stack_op(op: "push", value: BabyBear.big_int_push(d)))
          @nm.push(nil)
          @e.call(BabyBear.make_stack_op(op: "pick", depth: d))
          @nm.pop
          @nm.push(n)
        end

        # Roll an item from depth d to top.
        #
        # @param d [Integer] depth
        def roll(d)
          return if d == 0
          if d == 1
            swap
            return
          end
          if d == 2
            rot
            return
          end
          @e.call(BabyBear.make_stack_op(op: "push", value: BabyBear.big_int_push(d)))
          @nm.push(nil)
          @e.call(BabyBear.make_stack_op(op: "roll", depth: d))
          @nm.pop
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
      # Ext4 constants and additional field helpers
      # =================================================================

      # Quadratic non-residue W = 11 for BabyBear quartic extension.
      BB_W = 11

      # fieldMulConst: (a * c) mod p where c is a small constant.
      #
      # @param t [BBTracker]
      # @param a_name [String]
      # @param c [Integer]
      # @param result_name [String]
      def self.bb_field_mul_const(t, a_name, c, result_name)
        t.to_top(a_name)
        t.raw_block([a_name], "_bb_mc") do |e|
          e.call(make_stack_op(op: "push", value: big_int_push(c)))
          e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
        end
        t.to_top("_bb_mc")
        t.raw_block(["_bb_mc"], result_name) do |e|
          e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # =================================================================
      # Public emit functions -- entry points called from stack.rb
      # =================================================================

      # R-119 -- a witness-supplied field element must BE a field element,
      # aborting form.
      #
      # Nothing in this module or its KoalaBear twin ever compared anything: the
      # OP_LESSTHAN / OP_WITHIN / OP_GREATERTHANOREQUAL count in both was zero.
      # Every operand of the four scalar builtins and the eight ext4 entry
      # points is an unlock argument and went straight into
      # OP_ADD / OP_SUB / OP_MUL / OP_MOD.
      #
      # The `v` vs `v + p` half of the finding did NOT reproduce -- every
      # emitter reduces its result mod p, so bbFieldAdd(5+p, 0) and
      # bbFieldAdd(5, 0) both returned 5. The NEGATIVE half did: field_add and
      # field_mul reduce with a BARE OP_MOD on the documented assumption that
      # both operands are already in [0, p-1], and OP_MOD takes the sign of the
      # dividend. Measured before this gate, bbFieldAdd(-1, 0) returned -1 where
      # bbFieldAdd(p-1, 0) returned 2013265920 -- two different script numbers
      # for one residue, out of a builtin whose declared codomain is the field.
      # Script equality is numeric, so the escaped spelling breaks every
      # downstream comparison and every serialisation of the element.
      #
      # REJECT, not reduce, and gate the INPUT: a reduce would leave `v` and
      # `v + p` as two accepted spellings of one element, which is the aliasing
      # this finding is about. Gating the input makes the builtins canonical-in
      # / canonical-out, so the gate is idempotent under composition. ABORTING
      # because these are VALUE builtins -- the split R-117 drew for EC and
      # CL-BUG-095 set for the Point width. Public entry points only; the
      # internal helpers run hundreds of times on values canonical by
      # construction.
      def self.bb_emit_canon_verify(t, *names)
        names.each do |n|
          t.copy_to_top(n, "_cv")
          t.raw_block(["_cv"], nil) do |e|
            e.call(make_stack_op(op: "push", value: big_int_push(0)))
            e.call(make_stack_op(op: "push", value: big_int_push(BB_P)))
            e.call(make_stack_op(op: "opcode", code: "OP_WITHIN"))
            e.call(make_stack_op(op: "opcode", code: "OP_VERIFY"))
          end
        end
      end

      # Baby Bear field addition.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a + b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_add(emit)
        t = BBTracker.new(["a", "b"], emit)
        bb_emit_canon_verify(t, "a", "b")
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
        bb_emit_canon_verify(t, "a", "b")
        bb_field_sub(t, "a", "b", "result")
      end

      # Baby Bear field multiplication.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a * b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_mul(emit)
        t = BBTracker.new(["a", "b"], emit)
        bb_emit_canon_verify(t, "a", "b")
        bb_field_mul(t, "a", "b", "result")
      end

      # Baby Bear field multiplicative inverse.
      # Stack in: [..., a]
      # Stack out: [..., a^(p-2) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_field_inv(emit)
        t = BBTracker.new(["a"], emit)
        bb_emit_canon_verify(t, "a")
        bb_field_inv(t, "a", "result")
      end

      # =================================================================
      # Ext4 multiplication component emit functions
      # =================================================================
      # Quartic extension multiplication over BabyBear (p=2013265921, W=11).
      # Given a = (a0, a1, a2, a3) and b = (b0, b1, b2, b3):
      #   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
      #   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
      #   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
      #   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
      # Each emit function takes 8 args on stack and produces one component.

      # Ext4 mul component 0: r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p.
      # Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3] (b3 on top)
      # Stack out: [..., r0]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_mul_0(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3 b0 b1 b2 b3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3")

        # r0 = a0*b0 + 11*(a1*b3 + a2*b2 + a3*b1)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b0", "_b0")
        bb_field_mul(t, "_a0", "_b0", "_t0")     # a0*b0
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b3", "_b3")
        bb_field_mul(t, "_a1", "_b3", "_t1")     # a1*b3
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b2", "_b2")
        bb_field_mul(t, "_a2", "_b2", "_t2")     # a2*b2
        bb_field_add(t, "_t1", "_t2", "_t12")    # a1*b3 + a2*b2
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b1", "_b1")
        bb_field_mul(t, "_a3", "_b1", "_t3")     # a3*b1
        bb_field_add(t, "_t12", "_t3", "_cross") # a1*b3 + a2*b2 + a3*b1
        bb_field_mul_const(t, "_cross", BB_W, "_wcross") # W * cross
        bb_field_add(t, "_t0", "_wcross", "_r")  # a0*b0 + W*cross

        # Clean up: drop the 8 input values, keep only _r
        %w[a0 a1 a2 a3 b0 b1 b2 b3].each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 mul component 1: r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p.
      # Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3] (b3 on top)
      # Stack out: [..., r1]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_mul_1(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3 b0 b1 b2 b3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3")

        # r1 = a0*b1 + a1*b0 + 11*(a2*b3 + a3*b2)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b1", "_b1")
        bb_field_mul(t, "_a0", "_b1", "_t0")     # a0*b1
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b0", "_b0")
        bb_field_mul(t, "_a1", "_b0", "_t1")     # a1*b0
        bb_field_add(t, "_t0", "_t1", "_direct") # a0*b1 + a1*b0
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b3", "_b3")
        bb_field_mul(t, "_a2", "_b3", "_t2")     # a2*b3
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b2", "_b2")
        bb_field_mul(t, "_a3", "_b2", "_t3")     # a3*b2
        bb_field_add(t, "_t2", "_t3", "_cross")  # a2*b3 + a3*b2
        bb_field_mul_const(t, "_cross", BB_W, "_wcross") # W * cross
        bb_field_add(t, "_direct", "_wcross", "_r")

        # Clean up: drop the 8 input values, keep only _r
        %w[a0 a1 a2 a3 b0 b1 b2 b3].each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 mul component 2: r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p.
      # Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3] (b3 on top)
      # Stack out: [..., r2]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_mul_2(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3 b0 b1 b2 b3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3")

        # r2 = a0*b2 + a1*b1 + a2*b0 + 11*(a3*b3)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b2", "_b2")
        bb_field_mul(t, "_a0", "_b2", "_t0")     # a0*b2
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b1", "_b1")
        bb_field_mul(t, "_a1", "_b1", "_t1")     # a1*b1
        bb_field_add(t, "_t0", "_t1", "_sum01")
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b0", "_b0")
        bb_field_mul(t, "_a2", "_b0", "_t2")     # a2*b0
        bb_field_add(t, "_sum01", "_t2", "_direct")
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b3", "_b3")
        bb_field_mul(t, "_a3", "_b3", "_t3")     # a3*b3
        bb_field_mul_const(t, "_t3", BB_W, "_wcross") # W * a3*b3
        bb_field_add(t, "_direct", "_wcross", "_r")

        # Clean up: drop the 8 input values, keep only _r
        %w[a0 a1 a2 a3 b0 b1 b2 b3].each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 mul component 3: r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p.
      # Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3] (b3 on top)
      # Stack out: [..., r3]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_mul_3(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3 b0 b1 b2 b3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3")

        # r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b3", "_b3")
        bb_field_mul(t, "_a0", "_b3", "_t0")     # a0*b3
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b2", "_b2")
        bb_field_mul(t, "_a1", "_b2", "_t1")     # a1*b2
        bb_field_add(t, "_t0", "_t1", "_sum01")
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b1", "_b1")
        bb_field_mul(t, "_a2", "_b1", "_t2")     # a2*b1
        bb_field_add(t, "_sum01", "_t2", "_sum012")
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b0", "_b0")
        bb_field_mul(t, "_a3", "_b0", "_t3")     # a3*b0
        bb_field_add(t, "_sum012", "_t3", "_r")

        # Clean up: drop the 8 input values, keep only _r
        %w[a0 a1 a2 a3 b0 b1 b2 b3].each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # =================================================================
      # Ext4 inverse component emit functions
      # =================================================================
      # Tower-of-quadratic-extensions algorithm (matches Plonky3):
      #
      # View element as (even, odd) where even = (a0, a2), odd = (a1, a3)
      # in the quadratic extension F[X^2]/(X^4-W) = F'[Y]/(Y^2-W) where Y = X^2.
      #
      # norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
      # norm_1 = 2*a0*a2 - a1^2 - W*a3^2
      #
      # Quadratic inverse of (norm_0, norm_1):
      #   scalar = (norm_0^2 - W*norm_1^2)^(-1)
      #   inv_n0 = norm_0 * scalar
      #   inv_n1 = -norm_1 * scalar (i.e. (p - norm_1) * scalar)
      #
      # Then: result = conjugate(a) * inv_norm
      #   conjugate(a) = (a0, -a1, a2, -a3)
      #   out_even = quad_mul((a0, a2), (inv_n0, inv_n1))
      #   out_odd  = quad_mul((-a1, -a3), (inv_n0, inv_n1))
      #   r0 = out_even[0], r1 = -out_odd[0], r2 = out_even[1], r3 = -out_odd[1]

      # Shared inline preamble for ext4 inv: compute _inv_n0 and _inv_n1.
      # Matches the TypeScript emitExt4InvComponent steps 1-4 exactly.
      #
      # @param t [BBTracker]
      def self.bb_ext4_inv_preamble(t)
        # Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
        t.copy_to_top("a0", "_a0c")
        bb_field_sqr(t, "_a0c", "_a0sq")           # a0^2
        t.copy_to_top("a2", "_a2c")
        bb_field_sqr(t, "_a2c", "_a2sq")           # a2^2
        bb_field_mul_const(t, "_a2sq", BB_W, "_wa2sq") # W*a2^2
        bb_field_add(t, "_a0sq", "_wa2sq", "_n0a")    # a0^2 + W*a2^2
        t.copy_to_top("a1", "_a1c")
        t.copy_to_top("a3", "_a3c")
        bb_field_mul(t, "_a1c", "_a3c", "_a1a3")   # a1*a3
        bb_field_mul_const(t, "_a1a3", (BB_W * 2) % BB_P, "_2wa1a3") # 2*W*a1*a3
        bb_field_sub(t, "_n0a", "_2wa1a3", "_norm0") # norm_0

        # Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
        t.copy_to_top("a0", "_a0d")
        t.copy_to_top("a2", "_a2d")
        bb_field_mul(t, "_a0d", "_a2d", "_a0a2")   # a0*a2
        bb_field_mul_const(t, "_a0a2", 2, "_2a0a2") # 2*a0*a2
        t.copy_to_top("a1", "_a1d")
        bb_field_sqr(t, "_a1d", "_a1sq")           # a1^2
        bb_field_sub(t, "_2a0a2", "_a1sq", "_n1a") # 2*a0*a2 - a1^2
        t.copy_to_top("a3", "_a3d")
        bb_field_sqr(t, "_a3d", "_a3sq")           # a3^2
        bb_field_mul_const(t, "_a3sq", BB_W, "_wa3sq") # W*a3^2
        bb_field_sub(t, "_n1a", "_wa3sq", "_norm1") # norm_1

        # Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
        t.copy_to_top("_norm0", "_n0copy")
        bb_field_sqr(t, "_n0copy", "_n0sq")        # norm_0^2
        t.copy_to_top("_norm1", "_n1copy")
        bb_field_sqr(t, "_n1copy", "_n1sq")        # norm_1^2
        bb_field_mul_const(t, "_n1sq", BB_W, "_wn1sq") # W*norm_1^2
        bb_field_sub(t, "_n0sq", "_wn1sq", "_det") # norm_0^2 - W*norm_1^2
        bb_field_inv(t, "_det", "_scalar")         # scalar = det^(-1)

        # Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
        t.copy_to_top("_scalar", "_sc0")
        bb_field_mul(t, "_norm0", "_sc0", "_inv_n0") # inv_n0 = norm_0 * scalar

        # -norm_1 = (p - norm_1) mod p
        t.copy_to_top("_norm1", "_neg_n1_pre")
        t.push_int("_pval", BB_P)
        t.to_top("_neg_n1_pre")
        t.raw_block(["_pval", "_neg_n1_pre"], "_neg_n1_sub") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        end
        bb_field_mod(t, "_neg_n1_sub", "_neg_norm1")
        bb_field_mul(t, "_neg_norm1", "_scalar", "_inv_n1")
      end

      # Ext4 inv component 0: r0 = a0*inv_n0 + W*a2*inv_n1 mod p.
      # Stack in: [..., a0, a1, a2, a3] (a3 on top)
      # Stack out: [..., r0]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_inv_0(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3")
        bb_ext4_inv_preamble(t)

        # r0 = out_even[0] = a0*inv_n0 + W*a2*inv_n1
        t.copy_to_top("a0", "_ea0")
        t.copy_to_top("_inv_n0", "_ein0")
        bb_field_mul(t, "_ea0", "_ein0", "_ep0")   # a0*inv_n0
        t.copy_to_top("a2", "_ea2")
        t.copy_to_top("_inv_n1", "_ein1")
        bb_field_mul(t, "_ea2", "_ein1", "_ep1")   # a2*inv_n1
        bb_field_mul_const(t, "_ep1", BB_W, "_wep1") # W*a2*inv_n1
        bb_field_add(t, "_ep0", "_wep1", "_r")

        # Clean up: drop all intermediate and input values, keep only _r
        remaining = t.nm.select { |n| !n.nil? && n != "_r" }
        remaining.each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 inv component 1: r1 = -odd_part[0] where odd0 = a1*inv_n0 + W*a3*inv_n1.
      # Stack in: [..., a0, a1, a2, a3] (a3 on top)
      # Stack out: [..., r1]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_inv_1(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3")
        bb_ext4_inv_preamble(t)

        # odd0 = a1*inv_n0 + W*a3*inv_n1
        t.copy_to_top("a1", "_oa1")
        t.copy_to_top("_inv_n0", "_oin0")
        bb_field_mul(t, "_oa1", "_oin0", "_op0")   # a1*inv_n0
        t.copy_to_top("a3", "_oa3")
        t.copy_to_top("_inv_n1", "_oin1")
        bb_field_mul(t, "_oa3", "_oin1", "_op1")   # a3*inv_n1
        bb_field_mul_const(t, "_op1", BB_W, "_wop1") # W*a3*inv_n1
        bb_field_add(t, "_op0", "_wop1", "_odd0")
        # Negate: r = (0 - odd0) mod p
        t.push_int("_zero1", 0)
        bb_field_sub(t, "_zero1", "_odd0", "_r")

        # Clean up: drop all intermediate and input values, keep only _r
        remaining = t.nm.select { |n| !n.nil? && n != "_r" }
        remaining.each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 inv component 2: r2 = a0*inv_n1 + a2*inv_n0 mod p.
      # Stack in: [..., a0, a1, a2, a3] (a3 on top)
      # Stack out: [..., r2]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_inv_2(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3")
        bb_ext4_inv_preamble(t)

        # r2 = out_even[1] = a0*inv_n1 + a2*inv_n0
        t.copy_to_top("a0", "_ea0")
        t.copy_to_top("_inv_n1", "_ein1")
        bb_field_mul(t, "_ea0", "_ein1", "_ep0")   # a0*inv_n1
        t.copy_to_top("a2", "_ea2")
        t.copy_to_top("_inv_n0", "_ein0")
        bb_field_mul(t, "_ea2", "_ein0", "_ep1")   # a2*inv_n0
        bb_field_add(t, "_ep0", "_ep1", "_r")

        # Clean up: drop all intermediate and input values, keep only _r
        remaining = t.nm.select { |n| !n.nil? && n != "_r" }
        remaining.each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 inv component 3: r3 = -odd_part[1] where odd1 = a1*inv_n1 + a3*inv_n0.
      # Stack in: [..., a0, a1, a2, a3] (a3 on top)
      # Stack out: [..., r3]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bb_ext4_inv_3(emit)
        t = BBTracker.new(%w[a0 a1 a2 a3], emit)
        bb_emit_canon_verify(t, "a0", "a1", "a2", "a3")
        bb_ext4_inv_preamble(t)

        # odd1 = a1*inv_n1 + a3*inv_n0
        t.copy_to_top("a1", "_oa1")
        t.copy_to_top("_inv_n1", "_oin1")
        bb_field_mul(t, "_oa1", "_oin1", "_op0")   # a1*inv_n1
        t.copy_to_top("a3", "_oa3")
        t.copy_to_top("_inv_n0", "_oin0")
        bb_field_mul(t, "_oa3", "_oin0", "_op1")   # a3*inv_n0
        bb_field_add(t, "_op0", "_op1", "_odd1")
        # Negate: r = (0 - odd1) mod p
        t.push_int("_zero3", 0)
        bb_field_sub(t, "_zero3", "_odd1", "_r")

        # Clean up: drop all intermediate and input values, keep only _r
        remaining = t.nm.select { |n| !n.nil? && n != "_r" }
        remaining.each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # =================================================================
      # Dispatch
      # =================================================================

      BB_DISPATCH = {
        "bbFieldAdd" => method(:emit_bb_field_add),
        "bbFieldSub" => method(:emit_bb_field_sub),
        "bbFieldMul" => method(:emit_bb_field_mul),
        "bbFieldInv" => method(:emit_bb_field_inv),
        "bbExt4Mul0" => method(:emit_bb_ext4_mul_0),
        "bbExt4Mul1" => method(:emit_bb_ext4_mul_1),
        "bbExt4Mul2" => method(:emit_bb_ext4_mul_2),
        "bbExt4Mul3" => method(:emit_bb_ext4_mul_3),
        "bbExt4Inv0" => method(:emit_bb_ext4_inv_0),
        "bbExt4Inv1" => method(:emit_bb_ext4_inv_1),
        "bbExt4Inv2" => method(:emit_bb_ext4_inv_2),
        "bbExt4Inv3" => method(:emit_bb_ext4_inv_3),
      }.freeze

      # BB builtin function names.
      BB_BUILTIN_NAMES = Set.new(%w[
        bbFieldAdd bbFieldSub bbFieldMul bbFieldInv
        bbExt4Mul0 bbExt4Mul1 bbExt4Mul2 bbExt4Mul3
        bbExt4Inv0 bbExt4Inv1 bbExt4Inv2 bbExt4Inv3
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
