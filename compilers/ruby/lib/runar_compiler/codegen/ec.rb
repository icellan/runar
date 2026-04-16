# frozen_string_literal: true

# EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.
#
# Follows the slh_dsa.rb pattern: self-contained module imported by stack.rb.
# Uses an ECTracker (similar to SLHTracker) for named stack state tracking.
#
# Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
# Internal arithmetic uses Jacobian coordinates for scalar multiplication.
#
# Direct port of compilers/python/runar_compiler/codegen/ec.py

require "set"

module RunarCompiler
  module Codegen
    module EC
      # =================================================================
      # Constants
      # =================================================================

      # secp256k1 field prime p = 2^256 - 2^32 - 977
      EC_FIELD_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f

      # p - 2, used for Fermat's little theorem modular inverse
      EC_FIELD_P_MINUS_2 = EC_FIELD_P - 2

      # secp256k1 generator x-coordinate
      EC_GEN_X = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

      # secp256k1 generator y-coordinate
      EC_GEN_Y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

      # Convert an integer to a 32-byte big-endian binary string.
      #
      # @param n [Integer]
      # @return [String] 32-byte binary string
      def self.bigint_to_bytes32(n)
        hex = n.to_s(16).rjust(64, "0")
        [hex].pack("H*")
      end

      # -----------------------------------------------------------------
      # StackOp / PushValue helpers (avoid circular dependency with stack.rb)
      # -----------------------------------------------------------------

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

      # Build a PushValue hash.
      #
      # @param kind [String] "bigint", "bool", or "bytes"
      # @param kwargs [Hash] additional fields
      # @return [Hash] PushValue hash
      def self.make_push_value(kind:, **kwargs)
        result = { kind: kind }
        kwargs.each { |k, v| result[k] = v }
        result
      end

      # Build a PushValue for a big integer.
      #
      # @param n [Integer]
      # @return [Hash] PushValue hash
      def self.big_int_push(n)
        make_push_value(kind: "bigint", big_int: n)
      end

      # =================================================================
      # ECTracker -- named stack state tracker (mirrors TS ECTracker)
      # =================================================================

      class ECTracker
        # @return [Array<String>] named stack entries
        attr_accessor :nm
        # @return [Proc] emit callback
        attr_reader :e

        # @param init [Array<String>] initial stack names
        # @param emit [Proc] callback receiving a StackOp hash
        def initialize(init, emit)
          @nm = init.dup
          @e = emit
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
          raise "ECTracker: '#{name}' not on stack #{@nm}"
        end

        # Push raw bytes onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [String] binary string of bytes
        def push_bytes(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.make_push_value(kind: "bytes", bytes_val: v)))
          @nm.push(n)
        end

        # Push a big integer onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_big_int(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.make_push_value(kind: "bigint", big_int: v)))
          @nm.push(n)
        end

        # Push an integer onto the stack using big_int_push encoding.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_int(n, v)
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(v)))
          @nm.push(n)
        end

        # Duplicate top of stack.
        #
        # @param n [String] name for the duplicate
        def dup(n)
          @e.call(EC.make_stack_op(op: "dup"))
          @nm.push(n)
        end

        # Drop top of stack.
        def drop
          @e.call(EC.make_stack_op(op: "drop"))
          @nm.pop if @nm.length > 0
        end

        # Remove second-to-top stack element.
        def nip
          @e.call(EC.make_stack_op(op: "nip"))
          l = @nm.length
          if l >= 2
            @nm[l - 2..l - 1] = [@nm[l - 1]]
          end
        end

        # Copy second-to-top onto top.
        #
        # @param n [String] name for the copy
        def over(n)
          @e.call(EC.make_stack_op(op: "over"))
          @nm.push(n)
        end

        # Swap top two stack elements.
        def swap
          @e.call(EC.make_stack_op(op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
          end
        end

        # Rotate top three stack elements.
        def rot
          @e.call(EC.make_stack_op(op: "rot"))
          l = @nm.length
          if l >= 3
            r = @nm[l - 3]
            @nm.delete_at(l - 3)
            @nm.push(r)
          end
        end

        # Emit a raw opcode.
        #
        # @param code [String] opcode name (e.g. "OP_ADD")
        def op(code)
          @e.call(EC.make_stack_op(op: "opcode", code: code))
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
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(d)))
          @nm.push("")
          @e.call(EC.make_stack_op(op: "roll", depth: d))
          @nm.pop # pop the push placeholder
          idx = @nm.length - 1 - d
          r = @nm[idx]
          @nm.delete_at(idx)
          @nm.push(r)
        end

        # Pick (copy) an item from depth d to top.
        #
        # @param d [Integer] depth
        # @param n [String] name for the copy
        def pick(d, n)
          if d == 0
            dup(n)
            return
          end
          if d == 1
            over(n)
            return
          end
          @e.call(EC.make_stack_op(op: "push", value: EC.big_int_push(d)))
          @nm.push("")
          @e.call(EC.make_stack_op(op: "pick", depth: d))
          @nm.pop # pop the push placeholder
          @nm.push(n)
        end

        # Roll the named item to the top of the stack.
        #
        # @param name [String]
        def to_top(name)
          roll(find_depth(name))
        end

        # Copy the named item to the top of the stack.
        #
        # @param name [String] source name
        # @param n [String] name for the copy
        def copy_to_top(name, n)
          pick(find_depth(name), n)
        end

        # Move top of stack to alt stack.
        def to_alt
          op("OP_TOALTSTACK")
          @nm.pop if @nm.length > 0
        end

        # Pop from alt stack to main stack.
        #
        # @param n [String] name for the value
        def from_alt(n)
          op("OP_FROMALTSTACK")
          @nm.push(n)
        end

        # Rename the top of stack.
        #
        # @param n [String] new name
        def rename(n)
          @nm[-1] = n if @nm.length > 0
        end

        # Emit raw opcodes; tracker only records net stack effect.
        #
        # @param consume [Array<String>] names consumed from the stack
        # @param produce [String] name produced ("" means no output pushed)
        # @param fn [Proc] block receiving an emit callback
        def raw_block(consume, produce, fn)
          consume.reverse_each do
            @nm.pop if @nm.length > 0
          end
          fn.call(@e)
          @nm.push(produce) unless produce.empty?
        end

        # Emit if/else with tracked stack effect.
        #
        # @param cond_name [String] name of the condition value
        # @param then_fn [Proc] block receiving an emit callback for then-branch
        # @param else_fn [Proc] block receiving an emit callback for else-branch
        # @param result_name [String] name for the result ("" means no result)
        def emit_if(cond_name, then_fn, else_fn, result_name)
          to_top(cond_name)
          # condition consumed
          @nm.pop if @nm.length > 0
          then_ops = []
          else_ops = []
          then_fn.call(->(op) { then_ops.push(op) })
          else_fn.call(->(op) { else_ops.push(op) })
          @e.call(EC.make_stack_op(op: "if", then: then_ops, else_ops: else_ops))
          @nm.push(result_name) unless result_name.empty?
        end
      end

      # =================================================================
      # Field arithmetic helpers
      # =================================================================

      # Push the field prime p onto the stack as a script number.
      #
      # @param t [ECTracker]
      # @param name [String]
      def self.ec_push_field_p(t, name)
        t.push_big_int(name, EC_FIELD_P)
      end

      # Reduce TOS mod p, ensuring non-negative result.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_mod(t, a_name, result_name)
        t.to_top(a_name)
        ec_push_field_p(t, "_fmod_p")
        # (a % p + p) % p
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))   # a p a p
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))     # a p (a%p)
          e.call(make_stack_op(op: "rot"))                         # p (a%p) a
          e.call(make_stack_op(op: "drop"))                        # p (a%p)
          e.call(make_stack_op(op: "over"))                        # p (a%p) p
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))      # p (a%p+p)
          e.call(make_stack_op(op: "swap"))                        # (a%p+p) p
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))      # ((a%p+p)%p)
        }
        t.raw_block([a_name, "_fmod_p"], result_name, fn)
      end

      # Compute (a + b) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_add(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fadd_sum", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        ec_field_mod(t, "_fadd_sum", result_name)
      end

      # Compute (a - b) mod p (non-negative).
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_sub(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fsub_diff", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_SUB")) })
        ec_field_mod(t, "_fsub_diff", result_name)
      end

      # Compute (a * b) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.ec_field_mul(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fmul_prod", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        ec_field_mod(t, "_fmul_prod", result_name)
      end

      # Compute (a * c) mod p where c is a small constant.
      #
      # Uses OP_2MUL when c == 2 (single opcode, no push needed).
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param c [Integer] small constant multiplier
      # @param result_name [String]
      def self.ec_field_mul_const(t, a_name, c, result_name)
        t.to_top(a_name)
        t.raw_block([a_name], "_fmc_prod", ->(e) {
          if c == 2
            # Use OP_2MUL (single opcode, no push needed)
            e.call(make_stack_op(op: "opcode", code: "OP_2MUL"))
          else
            e.call(make_stack_op(op: "push", value: big_int_push(c)))
            e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
          end
        })
        ec_field_mod(t, "_fmc_prod", result_name)
      end

      # Compute (a * a) mod p.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_sqr(t, a_name, result_name)
        t.copy_to_top(a_name, "_fsqr_copy")
        ec_field_mul(t, a_name, "_fsqr_copy", result_name)
      end

      # Compute a^(p-2) mod p via square-and-multiply.
      #
      # Consumes a_name from the tracker.
      #
      # @param t [ECTracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.ec_field_inv(t, a_name, result_name)
        # p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
        # Bits 255..32: 224 bits, all 1 except bit 32 which is 0
        # Bits 31..0: 0xFFFFFC2D

        # Start: result = a (bit 255 = 1)
        t.copy_to_top(a_name, "_inv_r")
        # Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
        222.times do
          ec_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")
          t.copy_to_top(a_name, "_inv_a")
          ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
          t.rename("_inv_r")
        end
        # Bit 32 is 0: square only (no multiply)
        ec_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")
        # Bits 31 down to 0 of p-2
        low_bits = EC_FIELD_P_MINUS_2 & 0xFFFFFFFF
        31.downto(0) do |i|
          ec_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")
          if (low_bits >> i) & 1 == 1
            t.copy_to_top(a_name, "_inv_a")
            ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
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
      # Point decompose / compose
      # =================================================================

      # Emit inline byte reversal for a 32-byte value on TOS.
      #
      # @param e [Proc] emit callback
      def self.ec_emit_reverse32(e)
        # Push empty accumulator, swap with data
        e.call(make_stack_op(op: "opcode", code: "OP_0"))
        e.call(make_stack_op(op: "swap"))
        # 32 iterations: peel first byte, prepend to accumulator
        32.times do
          # Stack: [accum, remaining]
          e.call(make_stack_op(op: "push", value: big_int_push(1)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          # Stack: [accum, byte0, rest]
          e.call(make_stack_op(op: "rot"))
          # Stack: [byte0, rest, accum]
          e.call(make_stack_op(op: "rot"))
          # Stack: [rest, accum, byte0]
          e.call(make_stack_op(op: "swap"))
          # Stack: [rest, byte0, accum]
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          # Stack: [rest, byte0||accum]
          e.call(make_stack_op(op: "swap"))
          # Stack: [byte0||accum, rest]
        end
        # Stack: [reversed, empty]
        e.call(make_stack_op(op: "drop"))
      end

      # Decompose a 64-byte Point into (x_num, y_num) on stack.
      #
      # Consumes point_name, produces x_name and y_name.
      #
      # @param t [ECTracker]
      # @param point_name [String]
      # @param x_name [String]
      # @param y_name [String]
      def self.ec_decompose_point(t, point_name, x_name, y_name)
        t.to_top(point_name)
        # OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
        split_fn = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        }
        t.raw_block([point_name], "", split_fn)
        # Manually track the two new items
        t.nm.push("_dp_xb")
        t.nm.push("_dp_yb")

        # Convert y_bytes (on top) to num
        # Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
        convert_y = ->(e) {
          ec_emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_yb"], y_name, convert_y)

        # Convert x_bytes to num
        t.to_top("_dp_xb")
        convert_x = ->(e) {
          ec_emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_xb"], x_name, convert_x)

        # Stack: [yName, xName] -- swap to standard order [xName, yName]
        t.swap
      end

      # Compose (x_num, y_num) into a 64-byte Point.
      #
      # Consumes x_name and y_name, produces result_name.
      #
      # @param t [ECTracker]
      # @param x_name [String]
      # @param y_name [String]
      # @param result_name [String]
      def self.ec_compose_point(t, x_name, y_name, result_name)
        # Convert x to 32-byte big-endian
        t.to_top(x_name)
        convert_x = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(33)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          # Drop the sign byte (last byte) -- split at 32, keep left
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          ec_emit_reverse32(e)
        }
        t.raw_block([x_name], "_cp_xb", convert_x)

        # Convert y to 32-byte big-endian
        t.to_top(y_name)
        convert_y = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(33)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          ec_emit_reverse32(e)
        }
        t.raw_block([y_name], "_cp_yb", convert_y)

        # Cat: x_be || y_be (x is below y after the two to_top calls)
        t.to_top("_cp_xb")
        t.to_top("_cp_yb")
        t.raw_block(["_cp_xb", "_cp_yb"], result_name, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_CAT")) })
      end

      # =================================================================
      # Affine point addition (for ecAdd)
      # =================================================================

      # Perform affine point addition.
      #
      # Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
      #
      # @param t [ECTracker]
      def self.ec_affine_add(t)
        # s_num = qy - py
        t.copy_to_top("qy", "_qy1")
        t.copy_to_top("py", "_py1")
        ec_field_sub(t, "_qy1", "_py1", "_s_num")

        # s_den = qx - px
        t.copy_to_top("qx", "_qx1")
        t.copy_to_top("px", "_px1")
        ec_field_sub(t, "_qx1", "_px1", "_s_den")

        # s = s_num / s_den mod p
        ec_field_inv(t, "_s_den", "_s_den_inv")
        ec_field_mul(t, "_s_num", "_s_den_inv", "_s")

        # rx = s^2 - px - qx mod p
        t.copy_to_top("_s", "_s_keep")
        ec_field_sqr(t, "_s", "_s2")
        t.copy_to_top("px", "_px2")
        ec_field_sub(t, "_s2", "_px2", "_rx1")
        t.copy_to_top("qx", "_qx2")
        ec_field_sub(t, "_rx1", "_qx2", "rx")

        # ry = s * (px - rx) - py mod p
        t.copy_to_top("px", "_px3")
        t.copy_to_top("rx", "_rx2")
        ec_field_sub(t, "_px3", "_rx2", "_px_rx")
        ec_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
        t.copy_to_top("py", "_py2")
        ec_field_sub(t, "_s_px_rx", "_py2", "ry")

        # Clean up original points
        t.to_top("px")
        t.drop
        t.to_top("py")
        t.drop
        t.to_top("qx")
        t.drop
        t.to_top("qy")
        t.drop
      end

      # =================================================================
      # Jacobian point operations (for ecMul)
      # =================================================================

      # Perform Jacobian point doubling (a=0 for secp256k1).
      #
      # Expects jx, jy, jz on tracker. Replaces with updated values.
      #
      # @param t [ECTracker]
      def self.ec_jacobian_double(t)
        # Save copies of jx, jy, jz for later use
        t.copy_to_top("jy", "_jy_save")
        t.copy_to_top("jx", "_jx_save")
        t.copy_to_top("jz", "_jz_save")

        # A = jy^2
        ec_field_sqr(t, "jy", "_A")

        # B = 4 * jx * A
        t.copy_to_top("_A", "_A_save")
        ec_field_mul(t, "jx", "_A", "_xA")
        t.push_int("_four", 4)
        ec_field_mul(t, "_xA", "_four", "_B")

        # C = 8 * A^2
        ec_field_sqr(t, "_A_save", "_A2")
        t.push_int("_eight", 8)
        ec_field_mul(t, "_A2", "_eight", "_C")

        # D = 3 * X^2
        ec_field_sqr(t, "_jx_save", "_x2")
        t.push_int("_three", 3)
        ec_field_mul(t, "_x2", "_three", "_D")

        # nx = D^2 - 2*B
        t.copy_to_top("_D", "_D_save")
        t.copy_to_top("_B", "_B_save")
        ec_field_sqr(t, "_D", "_D2")
        t.copy_to_top("_B", "_B1")
        ec_field_mul_const(t, "_B1", 2, "_2B")
        ec_field_sub(t, "_D2", "_2B", "_nx")

        # ny = D*(B - nx) - C
        t.copy_to_top("_nx", "_nx_copy")
        ec_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
        ec_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
        ec_field_sub(t, "_D_B_nx", "_C", "_ny")

        # nz = 2 * Y * Z
        ec_field_mul(t, "_jy_save", "_jz_save", "_yz")
        ec_field_mul_const(t, "_yz", 2, "_nz")

        # Clean up leftovers: _B and old jz (only copied, never consumed)
        t.to_top("_B")
        t.drop
        t.to_top("jz")
        t.drop
        t.to_top("_nx")
        t.rename("jx")
        t.to_top("_ny")
        t.rename("jy")
        t.to_top("_nz")
        t.rename("jz")
      end

      # Convert Jacobian to affine coordinates.
      #
      # Consumes jx, jy, jz; produces rx_name, ry_name.
      #
      # @param t [ECTracker]
      # @param rx_name [String]
      # @param ry_name [String]
      def self.ec_jacobian_to_affine(t, rx_name, ry_name)
        ec_field_inv(t, "jz", "_zinv")
        t.copy_to_top("_zinv", "_zinv_keep")
        ec_field_sqr(t, "_zinv", "_zinv2")
        t.copy_to_top("_zinv2", "_zinv2_keep")
        ec_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3")
        ec_field_mul(t, "jx", "_zinv2_keep", rx_name)
        ec_field_mul(t, "jy", "_zinv3", ry_name)
      end

      # =================================================================
      # Jacobian mixed addition (P_jacobian + Q_affine)
      # =================================================================

      # Build Jacobian mixed-add ops for use inside OP_IF.
      #
      # Uses an inner ECTracker to leverage field arithmetic helpers.
      #
      # Stack layout: [..., ax, ay, _k, jx, jy, jz]
      # After:        [..., ax, ay, _k, jx', jy', jz']
      #
      # @param e [Proc] emit callback
      # @param t [ECTracker]
      def self.ec_build_jacobian_add_affine_inline(e, t)
        # Create inner tracker with cloned stack state
        it = ECTracker.new(t.nm.dup, e)

        # Save copies of values that get consumed but are needed later
        it.copy_to_top("jz", "_jz_for_z1cu")   # consumed by Z1sq, needed for Z1cu
        it.copy_to_top("jz", "_jz_for_z3")     # needed for Z3
        it.copy_to_top("jy", "_jy_for_y3")     # consumed by R, needed for Y3
        it.copy_to_top("jx", "_jx_for_u1h2")   # consumed by H, needed for U1H2

        # Z1sq = jz^2
        ec_field_sqr(it, "jz", "_Z1sq")

        # Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
        it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
        ec_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

        # U2 = ax * Z1sq_for_u2
        it.copy_to_top("ax", "_ax_c")
        ec_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

        # S2 = ay * Z1cu
        it.copy_to_top("ay", "_ay_c")
        ec_field_mul(it, "_ay_c", "_Z1cu", "_S2")

        # H = U2 - jx
        ec_field_sub(it, "_U2", "jx", "_H")

        # R = S2 - jy
        ec_field_sub(it, "_S2", "jy", "_R")

        # Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
        it.copy_to_top("_H", "_H_for_h3")
        it.copy_to_top("_H", "_H_for_z3")

        # H2 = H^2
        ec_field_sqr(it, "_H", "_H2")

        # Save H2 for U1H2
        it.copy_to_top("_H2", "_H2_for_u1h2")

        # H3 = H_for_h3 * H2
        ec_field_mul(it, "_H_for_h3", "_H2", "_H3")

        # U1H2 = _jx_for_u1h2 * H2_for_u1h2
        ec_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

        # Save R, U1H2, H3 for Y3 computation
        it.copy_to_top("_R", "_R_for_y3")
        it.copy_to_top("_U1H2", "_U1H2_for_y3")
        it.copy_to_top("_H3", "_H3_for_y3")

        # X3 = R^2 - H3 - 2*U1H2
        ec_field_sqr(it, "_R", "_R2")
        ec_field_sub(it, "_R2", "_H3", "_x3_tmp")
        ec_field_mul_const(it, "_U1H2", 2, "_2U1H2")
        ec_field_sub(it, "_x3_tmp", "_2U1H2", "_X3")

        # Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
        it.copy_to_top("_X3", "_X3_c")
        ec_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
        ec_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
        ec_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
        ec_field_sub(it, "_r_tmp", "_jy_h3", "_Y3")

        # Z3 = _jz_for_z3 * _H_for_z3
        ec_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

        # Rename results to jx/jy/jz
        it.to_top("_X3")
        it.rename("jx")
        it.to_top("_Y3")
        it.rename("jy")
        it.to_top("_Z3")
        it.rename("jz")
      end

      # =================================================================
      # Public entry points (called from stack lowerer)
      # =================================================================

      # Add two points.
      #
      # Stack in: [point_a, point_b] (b on top)
      # Stack out: [result_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_add(emit)
        t = ECTracker.new(["_pa", "_pb"], emit)
        ec_decompose_point(t, "_pa", "px", "py")
        ec_decompose_point(t, "_pb", "qx", "qy")
        ec_affine_add(t)
        ec_compose_point(t, "rx", "ry", "_result")
      end

      # Perform scalar multiplication P * k.
      #
      # Stack in: [point, scalar] (scalar on top)
      # Stack out: [result_point]
      #
      # Uses 256-iteration double-and-add with Jacobian coordinates.
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mul(emit)
        t = ECTracker.new(["_pt", "_k"], emit)
        # Decompose to affine base point
        ec_decompose_point(t, "_pt", "ax", "ay")

        # k' = k + 3n: guarantees bit 257 is set.
        # k in [1, n-1], so k+3n in [3n+1, 4n-1]. Since 3n > 2^257, bit 257
        # is always 1. Adding 3n (= 0 mod n) preserves the EC point: k*G = (k+3n)*G.
        curve_n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        t.to_top("_k")
        t.push_big_int("_n", curve_n)
        t.raw_block(["_k", "_n"], "_kn", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_big_int("_n2", curve_n)
        t.raw_block(["_kn", "_n2"], "_kn2", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_big_int("_n3", curve_n)
        t.raw_block(["_kn2", "_n3"], "_kn3", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.rename("_k")

        # Init accumulator = P (bit 257 of k+3n is always 1)
        t.copy_to_top("ax", "jx")
        t.copy_to_top("ay", "jy")
        t.push_int("jz", 1)

        # 257 iterations: bits 256 down to 0
        256.downto(0) do |bit|
          # Double accumulator
          ec_jacobian_double(t)

          # Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
          t.copy_to_top("_k", "_k_copy")
          if bit == 1
            # Single-bit shift: OP_2DIV (no push needed)
            t.raw_block(["_k_copy"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_2DIV")) })
          elsif bit > 1
            # Multi-bit shift: push shift amount, OP_RSHIFTNUM
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_RSHIFTNUM")) })
          else
            t.rename("_shifted")
          end
          t.push_int("_two", 2)
          t.raw_block(["_shifted", "_two"], "_bit", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) })

          # Move _bit to TOS and remove from tracker BEFORE generating add ops,
          # because OP_IF consumes _bit and the add ops run with _bit already gone.
          t.to_top("_bit")
          t.nm.pop # _bit consumed by IF
          add_ops = []
          add_emit = ->(op) { add_ops.push(op) }
          ec_build_jacobian_add_affine_inline(add_emit, t)
          emit.call(make_stack_op(op: "if", then: add_ops, else_ops: []))
        end

        # Convert Jacobian to affine
        ec_jacobian_to_affine(t, "_rx", "_ry")

        # Clean up base point and scalar
        t.to_top("ax")
        t.drop
        t.to_top("ay")
        t.drop
        t.to_top("_k")
        t.drop

        # Compose result
        ec_compose_point(t, "_rx", "_ry", "_result")
      end

      # Perform scalar multiplication G * k.
      #
      # Stack in: [scalar]
      # Stack out: [result_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mul_gen(emit)
        # Push generator point as 64-byte blob, then delegate to ecMul
        g_point = bigint_to_bytes32(EC_GEN_X) + bigint_to_bytes32(EC_GEN_Y)
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: g_point)))
        emit.call(make_stack_op(op: "swap")) # [point, scalar]
        emit_ec_mul(emit)
      end

      # Negate a point (x, p - y).
      #
      # Stack in: [point]
      # Stack out: [negated_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_negate(emit)
        t = ECTracker.new(["_pt"], emit)
        ec_decompose_point(t, "_pt", "_nx", "_ny")
        ec_push_field_p(t, "_fp")
        ec_field_sub(t, "_fp", "_ny", "_neg_y")
        ec_compose_point(t, "_nx", "_neg_y", "_result")
      end

      # Check if point is on secp256k1 (y^2 = x^3 + 7 mod p).
      #
      # Stack in: [point]
      # Stack out: [boolean]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_on_curve(emit)
        t = ECTracker.new(["_pt"], emit)
        ec_decompose_point(t, "_pt", "_x", "_y")

        # lhs = y^2
        ec_field_sqr(t, "_y", "_y2")

        # rhs = x^3 + 7
        t.copy_to_top("_x", "_x_copy")
        ec_field_sqr(t, "_x", "_x2")
        ec_field_mul(t, "_x2", "_x_copy", "_x3")
        t.push_int("_seven", 7)
        ec_field_add(t, "_x3", "_seven", "_rhs")

        # Compare
        t.to_top("_y2")
        t.to_top("_rhs")
        t.raw_block(["_y2", "_rhs"], "_result", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) })
      end

      # Compute ((value % mod) + mod) % mod.
      #
      # Stack in: [value, mod]
      # Stack out: [result]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_mod_reduce(emit)
        emit.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(make_stack_op(op: "rot"))
        emit.call(make_stack_op(op: "drop"))
        emit.call(make_stack_op(op: "over"))
        emit.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
      end

      # Encode a point as a 33-byte compressed pubkey.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [compressed (33 bytes)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_encode_compressed(emit)
        # Split at 32: [x_bytes, y_bytes]
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        # Get last byte of y for parity
        emit.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
        emit.call(make_stack_op(op: "push", value: big_int_push(1)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        # Stack: [x_bytes, y_prefix, last_byte]
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        emit.call(make_stack_op(op: "push", value: big_int_push(2)))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        # Stack: [x_bytes, y_prefix, parity]
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop")) # drop y_prefix
        # Stack: [x_bytes, parity]
        emit.call(make_stack_op(
          op: "if",
          then: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x03".b))],
          else_ops: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x02".b))]
        ))
        # Stack: [x_bytes, prefix_byte]
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      # Convert (x: bigint, y: bigint) to a 64-byte Point.
      #
      # Stack in: [x_num, y_num] (y on top)
      # Stack out: [point_bytes (64 bytes)]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_make_point(emit)
        # Convert y to 32 bytes big-endian
        emit.call(make_stack_op(op: "push", value: big_int_push(33)))
        emit.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Stack: [x_num, y_be]
        emit.call(make_stack_op(op: "swap"))
        # Stack: [y_be, x_num]
        emit.call(make_stack_op(op: "push", value: big_int_push(33)))
        emit.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Stack: [y_be, x_be]
        emit.call(make_stack_op(op: "swap"))
        # Stack: [x_be, y_be]
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      # Extract the x-coordinate from a Point.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [x as bigint]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_point_x(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Append 0x00 sign byte to ensure unsigned interpretation
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
      end

      # Extract the y-coordinate from a Point.
      #
      # Stack in: [point (64 bytes)]
      # Stack out: [y as bigint]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_ec_point_y(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop"))
        ec_emit_reverse32(emit)
        # Append 0x00 sign byte to ensure unsigned interpretation
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
      end

      # =================================================================
      # Dispatch table (called from stack.rb)
      # =================================================================

      EC_BUILTIN_NAMES = %w[
        ecAdd ecMul ecMulGen
        ecNegate ecOnCurve ecModReduce
        ecEncodeCompressed ecMakePoint
        ecPointX ecPointY
      ].to_set.freeze

      # Return true if name is a recognized EC builtin function.
      #
      # @param name [String]
      # @return [Boolean]
      def self.is_ec_builtin(name)
        EC_BUILTIN_NAMES.include?(name)
      end

      EC_DISPATCH = {
        "ecAdd" => method(:emit_ec_add),
        "ecMul" => method(:emit_ec_mul),
        "ecMulGen" => method(:emit_ec_mul_gen),
        "ecNegate" => method(:emit_ec_negate),
        "ecOnCurve" => method(:emit_ec_on_curve),
        "ecModReduce" => method(:emit_ec_mod_reduce),
        "ecEncodeCompressed" => method(:emit_ec_encode_compressed),
        "ecMakePoint" => method(:emit_ec_make_point),
        "ecPointX" => method(:emit_ec_point_x),
        "ecPointY" => method(:emit_ec_point_y),
      }.freeze

      # Call the appropriate EC emit function for func_name.
      #
      # @param func_name [String]
      # @param emit [Proc] callback receiving a StackOp hash
      # @raise [RuntimeError] if func_name is not a known EC builtin
      def self.dispatch_ec_builtin(func_name, emit)
        fn = EC_DISPATCH[func_name]
        raise "unknown EC builtin: #{func_name}" if fn.nil?
        fn.call(emit)
      end
    end
  end
end
