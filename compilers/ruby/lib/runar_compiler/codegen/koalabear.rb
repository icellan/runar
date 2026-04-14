# frozen_string_literal: true

# KoalaBear field arithmetic codegen — KoalaBear prime field operations
# for Bitcoin Script.
#
# Follows the babybear.rb pattern: self-contained module imported by stack.rb.
# Uses a KBTracker for named stack state tracking.
#
# KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433 (0x7f000001)
# Used by SP1 v6 STARK proofs (StackedBasefold verification).
#
# All values fit in a single BSV script number (31-bit prime).
# No multi-limb arithmetic needed.
#
# Direct port of compilers/go/codegen/koalabear.go

module RunarCompiler
  module Codegen
    module KoalaBear
      # =================================================================
      # Constants
      # =================================================================

      # KoalaBear field prime p = 2^31 - 2^24 + 1
      KB_P = 2_130_706_433

      # p - 2, used for Fermat's little theorem modular inverse
      KB_P_MINUS_2 = 2_130_706_431

      # Quadratic non-residue W = 3 used for ext4 (irreducible x^4 - 3)
      KB_W = 3

      # =================================================================
      # StackOp / PushValue helpers (same pattern as BabyBear module)
      # =================================================================

      def self.make_stack_op(op:, **kwargs)
        result = { op: op }
        kwargs.each { |k, v| result[k] = v }
        result
      end

      def self.big_int_push(n)
        { kind: "bigint", big_int: n }
      end

      # =================================================================
      # KBTracker — named stack state tracker (mirrors BBTracker)
      # =================================================================

      class KBTracker
        # @return [Array<String, nil>] named stack entries
        attr_accessor :nm

        # @param init [Array<String>] initial stack names
        # @param emit [Proc] callback receiving a StackOp hash
        def initialize(init, emit)
          @nm = init.dup
          @e = emit
          @prime_cache_active = false
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
          raise "KBTracker: '#{name}' not on stack #{@nm}"
        end

        # Push a big integer onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_int(n, v)
          @e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(v)))
          @nm.push(n)
        end

        # Duplicate top of stack.
        #
        # @param n [String] name for the duplicate
        def dup(n)
          @e.call(KoalaBear.make_stack_op(op: "dup"))
          @nm.push(n)
        end

        # Drop top of stack.
        def drop
          @e.call(KoalaBear.make_stack_op(op: "drop"))
          @nm.pop if @nm.length > 0
        end

        # Remove second-to-top stack element.
        def nip
          @e.call(KoalaBear.make_stack_op(op: "nip"))
          l = @nm.length
          if l >= 2
            @nm[l - 2..l - 1] = [@nm[l - 1]]
          end
        end

        # Copy second-to-top onto top.
        #
        # @param n [String] name for the copy
        def over(n)
          @e.call(KoalaBear.make_stack_op(op: "over"))
          @nm.push(n)
        end

        # Swap top two stack elements.
        def swap
          @e.call(KoalaBear.make_stack_op(op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
          end
        end

        # Rotate top three stack elements.
        def rot
          @e.call(KoalaBear.make_stack_op(op: "rot"))
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
          @e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(d)))
          @nm.push(nil)
          @e.call(KoalaBear.make_stack_op(op: "pick", depth: d))
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
          @e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(d)))
          @nm.push(nil)
          @e.call(KoalaBear.make_stack_op(op: "roll", depth: d))
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

        # Push the KoalaBear prime to the alt-stack for caching.
        # All subsequent field operations will use the cached prime instead of pushing fresh.
        def push_prime_cache
          @e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(KB_P)))
          @e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          @prime_cache_active = true
        end

        # Remove the cached prime from the alt-stack.
        def pop_prime_cache
          @e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
          @e.call(KoalaBear.make_stack_op(op: "drop"))
          @prime_cache_active = false
        end

        # Emit the field prime onto the stack — either from cache or fresh push.
        #
        # @param e [Proc] emit callback
        def emit_prime(e)
          if @prime_cache_active
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(KoalaBear.make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
          else
            e.call(KoalaBear.make_stack_op(op: "push", value: KoalaBear.big_int_push(KB_P)))
          end
        end
      end

      # =================================================================
      # Field arithmetic internals
      # =================================================================

      # kbFieldMod: ensure value is in [0, p).
      # Pattern: (a % p + p) % p — handles negative values from sub.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.kb_field_mod(t, a_name, result_name)
        t.to_top(a_name)
        t.raw_block([a_name], result_name) do |e|
          # (a % p + p) % p
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # kbFieldAddUnreduced: a + b WITHOUT modular reduction.
      # Result is in [0, 2p-2]. Safe for inputs consumed immediately by mul.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.kb_field_add_unreduced(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], result_name) do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        end
      end

      # kbFieldAdd: (a + b) mod p.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.kb_field_add(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_kb_add") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        end
        # Sum of two values in [0, p-1] is always non-negative, simple OP_MOD suffices
        t.to_top("_kb_add")
        t.raw_block(["_kb_add"], result_name) do |e|
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # kbFieldSub: (a - b) mod p (non-negative).
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.kb_field_sub(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_kb_diff") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        end
        # Difference can be negative, need full mod-reduce
        kb_field_mod(t, "_kb_diff", result_name)
      end

      # kbFieldMul: (a * b) mod p.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.kb_field_mul(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_kb_prod") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
        end
        # Product of two non-negative values is non-negative, simple OP_MOD
        t.to_top("_kb_prod")
        t.raw_block(["_kb_prod"], result_name) do |e|
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # kbFieldSqr: (a * a) mod p.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.kb_field_sqr(t, a_name, result_name)
        t.copy_to_top(a_name, "_kb_sqr_copy")
        kb_field_mul(t, a_name, "_kb_sqr_copy", result_name)
      end

      # kbFieldInv: a^(p-2) mod p via square-and-multiply (Fermat's little theorem).
      # p-2 = 2130706431 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
      # 31 bits, popcount 30.
      # ~30 squarings + ~29 multiplies = ~59 compound operations.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.kb_field_inv(t, a_name, result_name)
        # Start: result = a (for MSB bit 30 = 1)
        t.copy_to_top(a_name, "_inv_r")

        # Process bits 29 down to 0 (30 bits)
        p_minus_2 = KB_P_MINUS_2
        29.downto(0) do |i|
          # Always square
          kb_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")

          # Multiply if bit is set
          if (p_minus_2 >> i) & 1 == 1
            t.copy_to_top(a_name, "_inv_a")
            kb_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")
          end
        end

        # Clean up original input and rename result
        t.to_top(a_name)
        t.drop
        t.to_top("_inv_r")
        t.rename(result_name)
      end

      # kbFieldMulConst: (a * c) mod p where c is a small constant.
      # Uses OP_2MUL when c==2 and OP_LSHIFTNUM when c is a power of 2 > 2.
      #
      # @param t [KBTracker]
      # @param a_name [String]
      # @param c [Integer]
      # @param result_name [String]
      def self.kb_field_mul_const(t, a_name, c, result_name)
        t.to_top(a_name)
        if c == 2
          t.raw_block([a_name], "_kb_mc") do |e|
            e.call(make_stack_op(op: "opcode", code: "OP_2MUL"))
          end
        elsif c > 2 && (c & (c - 1)) == 0
          # c is a power of 2 > 2 — use LSHIFTNUM
          shift = 0
          tmp = c
          shift += 1 while (tmp >>= 1) > 0
          # shift is now log2(c)
          t.raw_block([a_name], "_kb_mc") do |e|
            e.call(make_stack_op(op: "push", value: big_int_push(shift)))
            e.call(make_stack_op(op: "opcode", code: "OP_LSHIFTNUM"))
          end
        else
          t.raw_block([a_name], "_kb_mc") do |e|
            e.call(make_stack_op(op: "push", value: big_int_push(c)))
            e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
          end
        end
        # mod reduction — uses cached prime when available
        t.to_top("_kb_mc")
        t.raw_block(["_kb_mc"], result_name) do |e|
          t.emit_prime(e)
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        end
      end

      # =================================================================
      # Public emit functions — entry points called from stack.rb
      # =================================================================

      # KoalaBear field addition.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a + b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_kb_field_add(emit)
        t = KBTracker.new(["a", "b"], emit)
        kb_field_add(t, "a", "b", "result")
      end

      # KoalaBear field subtraction.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a - b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_kb_field_sub(emit)
        t = KBTracker.new(["a", "b"], emit)
        kb_field_sub(t, "a", "b", "result")
      end

      # KoalaBear field multiplication.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a * b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_kb_field_mul(emit)
        t = KBTracker.new(["a", "b"], emit)
        kb_field_mul(t, "a", "b", "result")
      end

      # KoalaBear field multiplicative inverse.
      # Stack in: [..., a]
      # Stack out: [..., a^(p-2) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_kb_field_inv(emit)
        t = KBTracker.new(["a"], emit)
        kb_field_inv(t, "a", "result")
      end

      # =================================================================
      # Ext4 multiplication component emit functions
      # =================================================================
      # Quartic extension multiplication over KoalaBear (p=2130706433, W=3).
      # Given a = (a0, a1, a2, a3) and b = (b0, b1, b2, b3):
      #   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
      #   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
      #   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
      #   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
      # Each emit function takes 8 args on stack and produces one component.

      # Shared ext4 mul component logic.
      #
      # @param emit [Proc] callback
      # @param component [Integer] 0..3
      def self.kb_ext4_mul_component(emit, component)
        t = KBTracker.new(%w[a0 a1 a2 a3 b0 b1 b2 b3], emit)

        case component
        when 0
          # r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
          t.copy_to_top("a0", "_a0"); t.copy_to_top("b0", "_b0")
          kb_field_mul(t, "_a0", "_b0", "_t0")     # a0*b0
          t.copy_to_top("a1", "_a1"); t.copy_to_top("b3", "_b3")
          kb_field_mul(t, "_a1", "_b3", "_t1")     # a1*b3
          t.copy_to_top("a2", "_a2"); t.copy_to_top("b2", "_b2")
          kb_field_mul(t, "_a2", "_b2", "_t2")     # a2*b2
          kb_field_add(t, "_t1", "_t2", "_t12")    # a1*b3 + a2*b2
          t.copy_to_top("a3", "_a3"); t.copy_to_top("b1", "_b1")
          kb_field_mul(t, "_a3", "_b1", "_t3")     # a3*b1
          kb_field_add(t, "_t12", "_t3", "_cross") # a1*b3 + a2*b2 + a3*b1
          kb_field_mul_const(t, "_cross", KB_W, "_wcross") # W * cross
          kb_field_add(t, "_t0", "_wcross", "_r")  # a0*b0 + W*cross

        when 1
          # r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
          t.copy_to_top("a0", "_a0"); t.copy_to_top("b1", "_b1")
          kb_field_mul(t, "_a0", "_b1", "_t0")     # a0*b1
          t.copy_to_top("a1", "_a1"); t.copy_to_top("b0", "_b0")
          kb_field_mul(t, "_a1", "_b0", "_t1")     # a1*b0
          kb_field_add(t, "_t0", "_t1", "_direct") # a0*b1 + a1*b0
          t.copy_to_top("a2", "_a2"); t.copy_to_top("b3", "_b3")
          kb_field_mul(t, "_a2", "_b3", "_t2")     # a2*b3
          t.copy_to_top("a3", "_a3"); t.copy_to_top("b2", "_b2")
          kb_field_mul(t, "_a3", "_b2", "_t3")     # a3*b2
          kb_field_add(t, "_t2", "_t3", "_cross")  # a2*b3 + a3*b2
          kb_field_mul_const(t, "_cross", KB_W, "_wcross") # W * cross
          kb_field_add(t, "_direct", "_wcross", "_r")

        when 2
          # r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
          t.copy_to_top("a0", "_a0"); t.copy_to_top("b2", "_b2")
          kb_field_mul(t, "_a0", "_b2", "_t0")     # a0*b2
          t.copy_to_top("a1", "_a1"); t.copy_to_top("b1", "_b1")
          kb_field_mul(t, "_a1", "_b1", "_t1")     # a1*b1
          kb_field_add(t, "_t0", "_t1", "_sum01")
          t.copy_to_top("a2", "_a2"); t.copy_to_top("b0", "_b0")
          kb_field_mul(t, "_a2", "_b0", "_t2")     # a2*b0
          kb_field_add(t, "_sum01", "_t2", "_direct")
          t.copy_to_top("a3", "_a3"); t.copy_to_top("b3", "_b3")
          kb_field_mul(t, "_a3", "_b3", "_t3")     # a3*b3
          kb_field_mul_const(t, "_t3", KB_W, "_wcross") # W * a3*b3
          kb_field_add(t, "_direct", "_wcross", "_r")

        when 3
          # r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
          t.copy_to_top("a0", "_a0"); t.copy_to_top("b3", "_b3")
          kb_field_mul(t, "_a0", "_b3", "_t0")     # a0*b3
          t.copy_to_top("a1", "_a1"); t.copy_to_top("b2", "_b2")
          kb_field_mul(t, "_a1", "_b2", "_t1")     # a1*b2
          kb_field_add(t, "_t0", "_t1", "_sum01")
          t.copy_to_top("a2", "_a2"); t.copy_to_top("b1", "_b1")
          kb_field_mul(t, "_a2", "_b1", "_t2")     # a2*b1
          kb_field_add(t, "_sum01", "_t2", "_sum012")
          t.copy_to_top("a3", "_a3"); t.copy_to_top("b0", "_b0")
          kb_field_mul(t, "_a3", "_b0", "_t3")     # a3*b0
          kb_field_add(t, "_sum012", "_t3", "_r")

        else
          raise "Invalid ext4 component: #{component}"
        end

        # Clean up: drop the 8 input values, keep only _r
        %w[a0 a1 a2 a3 b0 b1 b2 b3].each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 mul component 0: r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p.
      # Stack in: [..., a0, a1, a2, a3, b0, b1, b2, b3] (b3 on top)
      # Stack out: [..., r0]
      def self.emit_kb_ext4_mul_0(emit)
        kb_ext4_mul_component(emit, 0)
      end

      # Ext4 mul component 1: r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p.
      def self.emit_kb_ext4_mul_1(emit)
        kb_ext4_mul_component(emit, 1)
      end

      # Ext4 mul component 2: r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p.
      def self.emit_kb_ext4_mul_2(emit)
        kb_ext4_mul_component(emit, 2)
      end

      # Ext4 mul component 3: r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p.
      def self.emit_kb_ext4_mul_3(emit)
        kb_ext4_mul_component(emit, 3)
      end

      # =================================================================
      # Ext4 inverse component emit functions
      # =================================================================
      # Tower-of-quadratic-extensions algorithm:
      #
      # norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
      # norm_1 = 2*a0*a2 - a1^2 - W*a3^2
      #
      # Quadratic inverse of (norm_0, norm_1):
      #   scalar = (norm_0^2 - W*norm_1^2)^(-1)
      #   inv_n0 = norm_0 * scalar
      #   inv_n1 = -norm_1 * scalar
      #
      # Then:
      #   r0 = a0*inv_n0 + W*a2*inv_n1
      #   r1 = -(a1*inv_n0 + W*a3*inv_n1)
      #   r2 = a0*inv_n1 + a2*inv_n0
      #   r3 = -(a1*inv_n1 + a3*inv_n0)

      # Shared inline preamble for ext4 inv: compute _inv_n0 and _inv_n1.
      #
      # @param t [KBTracker]
      def self.kb_ext4_inv_preamble(t)
        # Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
        t.copy_to_top("a0", "_a0c")
        kb_field_sqr(t, "_a0c", "_a0sq")                           # a0^2
        t.copy_to_top("a2", "_a2c")
        kb_field_sqr(t, "_a2c", "_a2sq")                           # a2^2
        kb_field_mul_const(t, "_a2sq", KB_W, "_wa2sq")             # W*a2^2
        kb_field_add(t, "_a0sq", "_wa2sq", "_n0a")                 # a0^2 + W*a2^2
        t.copy_to_top("a1", "_a1c")
        t.copy_to_top("a3", "_a3c")
        kb_field_mul(t, "_a1c", "_a3c", "_a1a3")                   # a1*a3
        kb_field_mul_const(t, "_a1a3", 2 * KB_W, "_2wa1a3")        # 2*W*a1*a3
        kb_field_sub(t, "_n0a", "_2wa1a3", "_norm0")               # norm_0

        # Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
        t.copy_to_top("a0", "_a0d")
        t.copy_to_top("a2", "_a2d")
        kb_field_mul(t, "_a0d", "_a2d", "_a0a2")                   # a0*a2
        kb_field_mul_const(t, "_a0a2", 2, "_2a0a2")               # 2*a0*a2
        t.copy_to_top("a1", "_a1d")
        kb_field_sqr(t, "_a1d", "_a1sq")                           # a1^2
        kb_field_sub(t, "_2a0a2", "_a1sq", "_n1a")                # 2*a0*a2 - a1^2
        t.copy_to_top("a3", "_a3d")
        kb_field_sqr(t, "_a3d", "_a3sq")                           # a3^2
        kb_field_mul_const(t, "_a3sq", KB_W, "_wa3sq")             # W*a3^2
        kb_field_sub(t, "_n1a", "_wa3sq", "_norm1")               # norm_1

        # Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
        t.copy_to_top("_norm0", "_n0copy")
        kb_field_sqr(t, "_n0copy", "_n0sq")                        # norm_0^2
        t.copy_to_top("_norm1", "_n1copy")
        kb_field_sqr(t, "_n1copy", "_n1sq")                        # norm_1^2
        kb_field_mul_const(t, "_n1sq", KB_W, "_wn1sq")             # W*norm_1^2
        kb_field_sub(t, "_n0sq", "_wn1sq", "_det")                 # norm_0^2 - W*norm_1^2
        kb_field_inv(t, "_det", "_scalar")                         # scalar = det^(-1)

        # Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
        t.copy_to_top("_scalar", "_sc0")
        kb_field_mul(t, "_norm0", "_sc0", "_inv_n0")               # inv_n0 = norm_0 * scalar

        # -norm_1 = (p - norm_1) mod p
        t.copy_to_top("_norm1", "_neg_n1_pre")
        t.push_int("_pval", KB_P)
        t.to_top("_neg_n1_pre")
        t.raw_block(["_pval", "_neg_n1_pre"], "_neg_n1_sub") do |e|
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        end
        kb_field_mod(t, "_neg_n1_sub", "_neg_norm1")
        kb_field_mul(t, "_neg_norm1", "_scalar", "_inv_n1")
      end

      # Shared ext4 inv component logic.
      #
      # @param emit [Proc]
      # @param component [Integer] 0..3
      def self.kb_ext4_inv_component(emit, component)
        t = KBTracker.new(%w[a0 a1 a2 a3], emit)
        kb_ext4_inv_preamble(t)

        case component
        when 0
          # r0 = a0*inv_n0 + W*a2*inv_n1
          t.copy_to_top("a0", "_ea0")
          t.copy_to_top("_inv_n0", "_ein0")
          kb_field_mul(t, "_ea0", "_ein0", "_ep0")   # a0*inv_n0
          t.copy_to_top("a2", "_ea2")
          t.copy_to_top("_inv_n1", "_ein1")
          kb_field_mul(t, "_ea2", "_ein1", "_ep1")   # a2*inv_n1
          kb_field_mul_const(t, "_ep1", KB_W, "_wep1") # W*a2*inv_n1
          kb_field_add(t, "_ep0", "_wep1", "_r")

        when 1
          # r1 = -(a1*inv_n0 + W*a3*inv_n1)
          t.copy_to_top("a1", "_oa1")
          t.copy_to_top("_inv_n0", "_oin0")
          kb_field_mul(t, "_oa1", "_oin0", "_op0")   # a1*inv_n0
          t.copy_to_top("a3", "_oa3")
          t.copy_to_top("_inv_n1", "_oin1")
          kb_field_mul(t, "_oa3", "_oin1", "_op1")   # a3*inv_n1
          kb_field_mul_const(t, "_op1", KB_W, "_wop1") # W*a3*inv_n1
          kb_field_add(t, "_op0", "_wop1", "_odd0")
          # Negate: r = (0 - odd0) mod p
          t.push_int("_zero1", 0)
          kb_field_sub(t, "_zero1", "_odd0", "_r")

        when 2
          # r2 = a0*inv_n1 + a2*inv_n0
          t.copy_to_top("a0", "_ea0")
          t.copy_to_top("_inv_n1", "_ein1")
          kb_field_mul(t, "_ea0", "_ein1", "_ep0")   # a0*inv_n1
          t.copy_to_top("a2", "_ea2")
          t.copy_to_top("_inv_n0", "_ein0")
          kb_field_mul(t, "_ea2", "_ein0", "_ep1")   # a2*inv_n0
          kb_field_add(t, "_ep0", "_ep1", "_r")

        when 3
          # r3 = -(a1*inv_n1 + a3*inv_n0)
          t.copy_to_top("a1", "_oa1")
          t.copy_to_top("_inv_n1", "_oin1")
          kb_field_mul(t, "_oa1", "_oin1", "_op0")   # a1*inv_n1
          t.copy_to_top("a3", "_oa3")
          t.copy_to_top("_inv_n0", "_oin0")
          kb_field_mul(t, "_oa3", "_oin0", "_op1")   # a3*inv_n0
          kb_field_add(t, "_op0", "_op1", "_odd1")
          # Negate: r = (0 - odd1) mod p
          t.push_int("_zero3", 0)
          kb_field_sub(t, "_zero3", "_odd1", "_r")

        else
          raise "Invalid ext4 component: #{component}"
        end

        # Clean up: drop all intermediate and input values, keep only _r
        remaining = t.nm.select { |n| !n.nil? && n != "_r" }
        remaining.each { |n| t.to_top(n); t.drop }
        t.to_top("_r")
        t.rename("result")
      end

      # Ext4 inv component 0: r0 = a0*invN0 + W*a2*invN1.
      # Stack in: [..., a0, a1, a2, a3] (a3 on top)
      # Stack out: [..., r0]
      def self.emit_kb_ext4_inv_0(emit)
        kb_ext4_inv_component(emit, 0)
      end

      # Ext4 inv component 1: r1 = -(a1*invN0 + W*a3*invN1).
      def self.emit_kb_ext4_inv_1(emit)
        kb_ext4_inv_component(emit, 1)
      end

      # Ext4 inv component 2: r2 = a0*invN1 + a2*invN0.
      def self.emit_kb_ext4_inv_2(emit)
        kb_ext4_inv_component(emit, 2)
      end

      # Ext4 inv component 3: r3 = -(a1*invN1 + a3*invN0).
      def self.emit_kb_ext4_inv_3(emit)
        kb_ext4_inv_component(emit, 3)
      end

      # =================================================================
      # Dispatch
      # =================================================================

      KB_DISPATCH = {
        "kbFieldAdd" => method(:emit_kb_field_add),
        "kbFieldSub" => method(:emit_kb_field_sub),
        "kbFieldMul" => method(:emit_kb_field_mul),
        "kbFieldInv" => method(:emit_kb_field_inv),
        "kbExt4Mul0" => method(:emit_kb_ext4_mul_0),
        "kbExt4Mul1" => method(:emit_kb_ext4_mul_1),
        "kbExt4Mul2" => method(:emit_kb_ext4_mul_2),
        "kbExt4Mul3" => method(:emit_kb_ext4_mul_3),
        "kbExt4Inv0" => method(:emit_kb_ext4_inv_0),
        "kbExt4Inv1" => method(:emit_kb_ext4_inv_1),
        "kbExt4Inv2" => method(:emit_kb_ext4_inv_2),
        "kbExt4Inv3" => method(:emit_kb_ext4_inv_3),
      }.freeze

      # KB builtin function names.
      KB_BUILTIN_NAMES = Set.new(%w[
        kbFieldAdd kbFieldSub kbFieldMul kbFieldInv
        kbExt4Mul0 kbExt4Mul1 kbExt4Mul2 kbExt4Mul3
        kbExt4Inv0 kbExt4Inv1 kbExt4Inv2 kbExt4Inv3
      ]).freeze

      # Return true if +name+ is a KoalaBear builtin.
      #
      # @param name [String]
      # @return [Boolean]
      def self.kb_builtin?(name)
        KB_BUILTIN_NAMES.include?(name)
      end

      # Call the appropriate KB emit function for func_name.
      #
      # @param func_name [String]
      # @param emit [Proc] callback receiving a StackOp hash
      # @raise [RuntimeError] if func_name is not a known KB builtin
      def self.dispatch_kb_builtin(func_name, emit)
        fn = KB_DISPATCH[func_name]
        raise "unknown KoalaBear builtin: #{func_name}" if fn.nil?
        fn.call(emit)
      end
    end
  end
end
