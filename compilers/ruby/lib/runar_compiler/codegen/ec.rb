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
      # CL-BUG-095 -- length gate for a +Point+ argument, ABORTING form.
      #
      # A +Point+ is DEFINED as exactly +want+ bytes (x || y, big-endian, no
      # prefix). Nothing checked that: +Point+ carries no width in the builtin
      # table, and every one of these values arrives as an unlock argument, so
      # the blob is attacker-sized. Surplus bytes were then silently DISCARDED,
      # because +ec_decompose_point+ splits at the coordinate width and
      # +ec_emit_reverse32+ reverses exactly 32 bytes and drops whatever is left
      # over -- so +ecOnCurve(G || 0xff)+ returned TRUE and +ecEncodeCompressed+
      # took its parity bit from the surplus.
      #
      # This is NOT a new failure channel. An UNDER-length point already
      # aborted, by accident: +OP_SPLIT+ runs off the end of the value. The gate
      # makes the same outcome explicit, and extends it to the over-length case
      # that used to pass.
      #
      # Aborting is right for every Point consumer that produces a VALUE and has
      # no error channel to report through -- +ecAdd+, +ecMul+, +ecNegate+,
      # +ecPointX+, +ecPointY+, +ecEncodeCompressed+. There is no correct value
      # to return for a blob that is not a point. The PREDICATES (+ecOnCurve+
      # and friends) use +emit_point_length_gate+ below instead, because for
      # them "no" is an answer.
      #
      # @param e [Proc] emit callback
      # @param want [Integer] required byte width
      def self.emit_point_len_verify(e, want)
        e.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
        e.call(make_stack_op(op: "push", value: big_int_push(want)))
        e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUALVERIFY"))
      end

      # CL-BUG-095 -- length gate for a +Point+ argument, CLAMPING form: leaves
      # +[flag, clamped]+, where +clamped+ is the value forced to exactly +want+
      # bytes (+v || 00*want+ split at +want+, tail dropped) and +flag+ is
      # +OP_SIZE(v) == want+.
      #
      # Same shape, and the same reasoning, as +c_emit_length_gate+ in
      # p256_p384.rb: the clamp exists so the gate can stay a FLAG. It is used
      # by the on-curve predicates, whose whole job is to answer "is this an
      # acceptable point?" over untrusted bytes -- and for a wrong-length blob
      # the correct answer is +false+, not an aborted script. Aborting would
      # break +if (ecOnCurve(p)) { ... } else { ... }+, which is the exact idiom
      # this module's own comments tell contract authors to write. The caller
      # ANDs +flag+ into its boolean result, so whatever the clamped bytes
      # happen to compute can never make a wrong-length point certify as
      # on-curve.
      #
      # Branch-free: the emitted op sequence, and the tracker's static stack
      # model, are identical for every input length.
      #
      # @param t [ECTracker]
      # @param name [String] name of the point on the stack
      # @param want [Integer] required byte width
      # @param flag_name [String] name for the length flag
      def self.emit_point_length_gate(t, name, want, flag_name)
        t.to_top(name)
        t.raw_block([name], "", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
          e.call(make_stack_op(op: "push", value: big_int_push(want)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b * want)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "push", value: big_int_push(want)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
        })
        t.nm.push(flag_name)
        t.nm.push(name)
      end

      def self.ec_decompose_point(t, point_name, x_name, y_name)
        t.to_top(point_name)
        # OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top) -- but only
        # for a value that really is 64 bytes. CL-BUG-095: gate the width first,
        # here, so every consumer that decomposes a Point inherits the check.
        split_fn = ->(e) {
          emit_point_len_verify(e, 64)
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
      # R-117: a Point's two coordinates must be FIELD ELEMENTS, aborting form.
      #
      # ec_decompose_point BIN2NUMs each half of the blob as an unsigned
      # integer, so any value that fits in the coordinate width is accepted --
      # x + p included, whenever x + p < 2**256 (on secp256k1 that is every
      # x < 2**32 + 977). Downstream field arithmetic reduces mod p, so
      # (x+p)||y behaves as the point (x, y); ec_affine_add's two case selectors
      # do NOT reduce, and they are bare OP_NUMEQUAL on exactly these raw
      # values:
      #
      #   cond   = (px == qx) AND (py == qy)      "same point" -> tangent
      #   notinf = NOT(px == qx AND NOT cond)     "P and -P"   -> the O mask
      #
      # so for P and its alias both read 0, the chord path runs on two equal
      # points, den_chord = qx - px == 0 (mod p), and ec_field_inv is Fermat
      # with inv(0) = 0. Measured before this gate landed, x = 1: ecAdd(P, P)
      # gave the correct 2P and ecAdd(P, P') gave x = p-2 -- a script that
      # SUCCEEDED and returned a blob that is not a point. Both the doubling
      # case and the P + (-P) case are driven by these selectors, so both are
      # defeated by the same trick.
      #
      # REJECT rather than reduce: emit_ec_on_curve already answers "no" to a
      # non-canonical encoding, so reducing here would leave the predicate and
      # the value builtins disagreeing about whether the blob is a point at all.
      # This is also the policy CL-BUG-095 set for the WIDTH -- predicates clamp
      # and flag, value producers OP_VERIFY.
      #
      # Callers are the user-facing value builtins only; deliberately NOT folded
      # into ec_decompose_point, which also runs inside emit_ec_on_curve and
      # must stay total.
      def self.ec_emit_coord_canon_verify(t, x_name, y_name)
        t.copy_to_top(x_name, "_cc_x")
        ec_push_field_p(t, "_cc_px")
        t.raw_block(["_cc_x", "_cc_px"], "_cc_xok", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.copy_to_top(y_name, "_cc_y")
        ec_push_field_p(t, "_cc_py")
        t.raw_block(["_cc_y", "_cc_py"], "_cc_yok", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.raw_block(["_cc_xok", "_cc_yok"], "", lambda { |e|
          e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND"))
          e.call(make_stack_op(op: "opcode", code: "OP_VERIFY"))
        })
      end

      def self.ec_affine_add(t)
        # The chord slope s = (qy - py) / (qx - px) is undefined when P == Q:
        # the denominator is zero and the correct slope is the TANGENT,
        # 3px^2 / (2py). Without this, ecAdd(P, P) silently produced a wrong
        # point, so every contract that doubled deployed an unspendable script.
        #
        # Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR
        # are selected and the single expensive field_inv still runs once.
        # rx and ry below are already correct for doubling.
        #
        #   cond = (px == qx) AND (py == qy)   1 when doubling, else 0
        #   num  = cond ? 3*px^2 : (qy - py)
        #   den  = cond ? 2*py   : (qx - px)
        #
        # selected as `b + cond*(a - b)`, which needs no branch and keeps the
        # emitted op sequence identical on both paths.
        #
        # THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx
        # ALONE sends it down the tangent path and returns 2P -- an on-curve,
        # entirely plausible, WRONG point. Before the doubling fix the chord
        # path ran there, divided by zero (ec_field_inv is Fermat, inv(0) = 0)
        # and produced an OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))`
        # -- the idiom this codegen tells authors to write -- happened to
        # reject it. Selecting on px alone would have silently disarmed that.
        #
        # P + (-P) is the point at infinity, which affine x||y cannot
        # represent. This codegen already has a representation for O: the
        # ALL-ZERO blob, which is what `ecMul(P, 0n)` returns and what the
        # `ec-mulgen-linear` rewrite in optimizer/ec-rules.json produces for
        # k1 + k2 == 0 (mod n). So return that, by masking the result with
        # `notinf = NOT(px == qx AND NOT cond)`:
        #
        #   - it agrees with the rewrite, so the same source cannot give two
        #     answers depending on whether the optimizer fired;
        #   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate
        #     rejects it and the idiom above works again;
        #   - it adds no failure channel to what is a pure value-producing
        #     expression, the same reason ec_emit_scalar_reduce reduces
        #     instead of rejecting.
        #
        # The mask is a bare OP_MUL with no reduction: rx, ry are already in
        # [0, p) and notinf is 0 or 1, so the product is canonical either way.
        t.copy_to_top("px", "_px_eq")
        t.copy_to_top("qx", "_qx_eq")
        t.raw_block(["_px_eq", "_qx_eq"], "_xeq",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("py", "_py_eq")
        t.copy_to_top("qy", "_qy_eq")
        t.raw_block(["_py_eq", "_qy_eq"], "_yeq",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("_xeq", "_xeq_c")
        t.to_top("_yeq")
        t.raw_block(["_xeq_c", "_yeq"], "_cond",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })
        # notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and
        # the points are not equal, i.e. exactly the P == -Q case.
        t.to_top("_xeq")
        t.copy_to_top("_cond", "_cond_c")
        t.raw_block(["_xeq", "_cond_c"], "_notinf", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
          e.call(make_stack_op(op: "opcode", code: "OP_NOT"))
        })

        # chord numerator / denominator
        t.copy_to_top("qy", "_qy1")
        t.copy_to_top("py", "_py1")
        ec_field_sub(t, "_qy1", "_py1", "_num_chord")
        t.copy_to_top("qx", "_qx1")
        t.copy_to_top("px", "_px1")
        ec_field_sub(t, "_qx1", "_px1", "_den_chord")

        # tangent numerator / denominator: 3*px^2 and 2*py
        t.copy_to_top("px", "_px_t")
        ec_field_sqr(t, "_px_t", "_px_sq")
        ec_field_mul_const(t, "_px_sq", 3, "_num_tan")
        t.copy_to_top("py", "_py_t")
        ec_field_mul_const(t, "_py_t", 2, "_den_tan")

        # num = num_chord + cond*(num_tan - num_chord)
        t.copy_to_top("_num_chord", "_num_chord_c")
        ec_field_sub(t, "_num_tan", "_num_chord_c", "_num_diff")
        t.copy_to_top("_cond", "_cond_n")
        ec_field_mul(t, "_num_diff", "_cond_n", "_num_sel")
        ec_field_add(t, "_num_chord", "_num_sel", "_s_num")

        # den = den_chord + cond*(den_tan - den_chord)
        t.copy_to_top("_den_chord", "_den_chord_c")
        ec_field_sub(t, "_den_tan", "_den_chord_c", "_den_diff")
        t.to_top("_cond")
        t.rename("_cond_d")
        ec_field_mul(t, "_den_diff", "_cond_d", "_den_sel")
        ec_field_add(t, "_den_chord", "_den_sel", "_s_den")

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

        # CL-BUG-096: select over the infinity operands and the P == -Q case,
        # and consume px/py/qx/qy in doing so. This subsumes the standalone
        # `notinf` mask that used to live here. See emit_affine_infinity_select.
        emit_affine_infinity_select(t)
      end

      # CL-BUG-096 -- the infinity-operand case of affine addition, shared by
      # secp256k1 and the two NIST curves because it is pure integer masking
      # and touches no field parameter.
      #
      # The group law has an identity, and this codegen has a representation
      # for it: the ALL-ZERO blob. It is not a theoretical value -- the codegen
      # MANUFACTURES it, from `ecMul(P, k)` whenever k == 0 (mod n), from
      # ec_affine_add's own P + (-P) masking, and from the `ec-mul-zero` /
      # `ec-add-negate-cancel` rewrites in optimizer/ec-rules.json.
      # `ec_affine_add` nonetheless had no case for it: fed (G, O) it took the
      # chord path with s = Gy/Gx and returned an off-curve blob from a script
      # that SUCCEEDED.
      #
      # And the always-on EC optimizer already believed the right answer:
      # `ec-add-identity-right` / `-left` rewrite `ecAdd($x, INFINITY)` to
      # `$x`. So the same source meant "P" with the optimizer on and "garbage"
      # with it off. Fixing the adder rather than deleting the two rules is the
      # only option that works, because the rules cannot see a zero scalar that
      # only exists at runtime -- deleting them would leave the runtime path
      # just as wrong and rewrite nothing.
      #
      # Branch-free, in the style the rest of this adder uses. Exactly one of
      # the three masks is 1 and the other two are 0, so the sum selects one
      # term:
      #
      #   pinf = (px == 0) AND (py == 0)          P is O
      #   qinf = (qx == 0) AND (qy == 0)          Q is O
      #   usep = qinf AND NOT pinf                -> answer is P
      #   useq = pinf                             -> answer is Q  (covers O+O=O)
      #   user = notinf AND NOT(pinf OR qinf)     -> answer is the computed sum
      #
      # `user` folds in the pre-existing `notinf` mask (the P == -Q case), so
      # P + (-P) still yields the all-zero blob and nothing about that case
      # changes.
      #
      # Requiring BOTH coordinates to be zero is load-bearing, not
      # belt-and-braces. x = 0 has genuine curve points whenever the curve's b
      # is a quadratic residue -- (0, sqrt(b)) -- and testing x alone would map
      # them to O. y = 0 has none on any of these three curves (all have prime
      # order, so no point of order 2), but the conjunction makes that fact not
      # need to be true.
      #
      # Plain OP_MUL / OP_ADD with no field reduction: px, qx, rx are already
      # in [0, p) and the masks are 0 or 1, so each product and the sum are
      # canonical.
      #
      # Consumes px, py, qx, qy and the field-computed rx, ry; leaves the
      # selected rx, ry in their place.
      #
      # @param t [ECTracker]
      def self.emit_affine_infinity_select(t)
        # pinf = (px == 0) AND (py == 0)
        t.copy_to_top("px", "_px_z")
        t.push_int("_zero_px", 0)
        t.raw_block(["_px_z", "_zero_px"], "_pxz",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("py", "_py_z")
        t.push_int("_zero_py", 0)
        t.raw_block(["_py_z", "_zero_py"], "_pyz",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.raw_block(["_pxz", "_pyz"], "_pinf",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # qinf = (qx == 0) AND (qy == 0)
        t.copy_to_top("qx", "_qx_z")
        t.push_int("_zero_qx", 0)
        t.raw_block(["_qx_z", "_zero_qx"], "_qxz",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.copy_to_top("qy", "_qy_z")
        t.push_int("_zero_qy", 0)
        t.raw_block(["_qy_z", "_zero_qy"], "_qyz",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        t.raw_block(["_qxz", "_qyz"], "_qinf",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # usep = qinf AND NOT pinf
        t.copy_to_top("_qinf", "_usep_q")
        t.copy_to_top("_pinf", "_usep_p")
        t.raw_block(["_usep_q", "_usep_p"], "_usep", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_NOT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND"))
        })

        # useq = pinf
        t.copy_to_top("_pinf", "_useq")

        # user = notinf AND NOT(pinf OR qinf)
        t.to_top("_pinf")
        t.to_top("_qinf")
        t.raw_block(["_pinf", "_qinf"], "_anyinf",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLOR")) })
        t.to_top("_notinf")
        t.to_top("_anyinf")
        t.raw_block(["_notinf", "_anyinf"], "_user", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_NOT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND"))
        })

        # rx = px*usep + qx*useq + rx*user
        t.to_top("px")
        t.copy_to_top("_usep", "_usep_x")
        t.raw_block(["px", "_usep_x"], "_selx_p",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.to_top("qx")
        t.copy_to_top("_useq", "_useq_x")
        t.raw_block(["qx", "_useq_x"], "_selx_q",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.to_top("rx")
        t.copy_to_top("_user", "_user_x")
        t.raw_block(["rx", "_user_x"], "_selx_r",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.raw_block(["_selx_q", "_selx_r"], "_selx_qr",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.raw_block(["_selx_p", "_selx_qr"], "rx",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })

        # ry = py*usep + qy*useq + ry*user  (last use of each mask: consume them)
        t.to_top("py")
        t.to_top("_usep")
        t.raw_block(["py", "_usep"], "_sely_p",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.to_top("qy")
        t.to_top("_useq")
        t.raw_block(["qy", "_useq"], "_sely_q",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.to_top("ry")
        t.to_top("_user")
        t.raw_block(["ry", "_user"], "_sely_r",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        t.raw_block(["_sely_q", "_sely_r"], "_sely_qr",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.raw_block(["_sely_p", "_sely_qr"], "ry",
                    ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
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
        ec_jacobian_add_affine_body(ECTracker.new(t.nm.dup, e), false)
      end

      # The mixed-add itself, emitting through a tracker the caller owns.
      #
      # +keep_hr+ additionally leaves copies of H and R on the stack. They are
      # the exception detector: H = U2 - X1 and R = S2 - Y1 are both zero
      # exactly when the Jacobian accumulator is the same curve point as the
      # affine operand, the one case these formulas cannot compute (see
      # ec_build_jacobian_add_or_double_inline).
      def self.ec_jacobian_add_affine_body(it, keep_hr)
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

        if keep_hr
          it.copy_to_top("_H", "_H_keep")
          it.copy_to_top("_R", "_R_keep")
        end

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

      # Branchless select of one Jacobian coordinate: +add + cond*(dbl - add)+.
      # Same shape as the numerator/denominator select in ec_affine_add, so both
      # paths emit the identical op sequence and the tracker's static stack
      # model holds. Consumes add_name, dbl_name and cond_name.
      def self.ec_select_coord(t, add_name, dbl_name, cond_name, result_name)
        t.copy_to_top(add_name, "_sel_add_c")
        ec_field_sub(t, dbl_name, "_sel_add_c", "_sel_diff")
        ec_field_mul(t, "_sel_diff", cond_name, "_sel_scaled")
        ec_field_add(t, add_name, "_sel_scaled", result_name)
      end

      # The ladder's LAST conditional step: mixed-add, but correct when the
      # accumulator already equals the point being added.
      #
      # The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when
      # the two operands are the same curve point H = 0, so Z3 = Z1*H = 0 -- the
      # point at infinity -- and since ec_field_inv is Fermat (inv(0) = 0),
      # ec_jacobian_to_affine turns that into the ALL-ZERO point instead of 2P.
      # ecMul(P, 2n) and ecMulGen(2n) returned 64 zero bytes.
      #
      # WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
      # c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
      # (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the
      # degenerate cases are exactly c_i == 2 (mod n) -- accumulator == P -- and
      # c_i == 0 or 1 (mod n) -- accumulator == -P or O. c_i ranges over a
      # CONTIGUOUS interval determined only by i, so this is decidable by
      # interval arithmetic rather than by sampling, and over the whole domain
      # k in [0, n-1] only two steps qualify, both at i = 0:
      #
      #   k = 2  -> c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P.
      #   k = 0  -> c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
      #             true result the point at infinity, which affine coordinates
      #             cannot represent; it stays the all-zero point, as before.
      #
      # At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] -- the lower bound is 3n, not
      # 3n+1, because the reduce puts k = 0 in the domain -- and that interval
      # contains no value == 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is
      # even, so no add runs. Handling H == 0 at every one of the 257 steps
      # would cost ~70% more script bytes; handling it here costs 0.26%.
      #
      # THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
      # because emit_ec_mul reduces k mod n before adding 3n. That reduce landed
      # one commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS
      # OWN IS UNSOUND: a last-step-only select while the scalar is still
      # unbounded leaves c_i free to hit 0, 1 or 2 (mod n) at other steps. The
      # two commits must land together and must never be bisected,
      # cherry-picked or reverted apart.
      #
      # The interval argument does 100% of the work; there is no defence in
      # depth here. In particular c_i == 1 (mod n) -- a pre-add accumulator of
      # O -- is UNREACHABLE, not handled: were it reachable the select would
      # still take the ADD path, because O is carried as Z1 = 0, which makes
      # U2 = 0 and H = -X1 != 0. Anything that changes the +3n offset, the
      # iteration count or the reduce must redo the interval check, not assume
      # this still holds.
      #
      # This is NOT a "no honest input hits it" argument: the operand P is
      # caller-supplied but cannot move the exception, because the condition
      # depends only on c_i mod ord(P) and ord(P) = n for every point on the
      # curve. Points that are NOT on the curve carry no such guarantee -- gate
      # untrusted input on ecOnCurve first.
      #
      # Stack layout: [..., ax, ay, _k, jx, jy, jz] -- same in and out.
      def self.ec_build_jacobian_add_or_double_inline(e, t)
        it = ECTracker.new(t.nm.dup, e)

        # Keep the pre-add accumulator: it is what must be DOUBLED in the
        # exceptional case, and the add below consumes jx/jy/jz.
        it.copy_to_top("jx", "_sx")
        it.copy_to_top("jy", "_sy")
        it.copy_to_top("jz", "_sz")

        ec_jacobian_add_affine_body(it, true)

        # cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
        # accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
        # signals the point at infinity.
        it.to_top("_H_keep")
        it.push_int("_zero_h", 0)
        it.raw_block(["_H_keep", "_zero_h"], "_h_is0",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        it.to_top("_R_keep")
        it.push_int("_zero_r", 0)
        it.raw_block(["_R_keep", "_zero_r"], "_r_is0",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL")) })
        it.to_top("_h_is0")
        it.to_top("_r_is0")
        it.raw_block(["_h_is0", "_r_is0"], "_cond",
                     ->(e2) { e2.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # Move the add result aside so ec_jacobian_double can work on jx/jy/jz
        # again, this time holding the saved accumulator.
        it.to_top("jx")
        it.rename("_add_x")
        it.to_top("jy")
        it.rename("_add_y")
        it.to_top("jz")
        it.rename("_add_z")
        it.to_top("_sx")
        it.rename("jx")
        it.to_top("_sy")
        it.rename("jy")
        it.to_top("_sz")
        it.rename("jz")
        ec_jacobian_double(it)
        it.to_top("jx")
        it.rename("_dbl_x")
        it.to_top("jy")
        it.rename("_dbl_y")
        it.to_top("jz")
        it.rename("_dbl_z")

        it.copy_to_top("_cond", "_cond_x")
        ec_select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx")
        it.copy_to_top("_cond", "_cond_y")
        ec_select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy")
        it.to_top("_cond")
        it.rename("_cond_z")
        ec_select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz")
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
        # R-117: ec_affine_add's selectors compare these four values RAW.
        ec_emit_coord_canon_verify(t, "px", "py")
        ec_emit_coord_canon_verify(t, "qx", "qy")
        ec_affine_add(t)
        ec_compose_point(t, "rx", "ry", "_result")
      end

      # Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.
      #
      # OP_MOD takes the sign of the DIVIDEND, so `k mod n` alone lands in
      # (-n, n); the `+ n, mod n` normalises the negative half. One push of n
      # covers both reductions -- the same shape as `emit_ec_mod_reduce`.
      #
      # Without it, `emit_ec_mul`'s ladder is only correct while
      # 2^257 <= k + 3n < 2^258: a scalar >= ~n sets bit 258, the 257-iteration
      # loop never sees it, and the ladder returns a DIFFERENT multiple of P
      # rather than failing. Scalars are contract input, so that is
      # attacker-chosen. Reducing costs 1 push + 8 opcodes (42 bytes) against a
      # ~429 KB script, and makes k >= n, k < 0 and k = 0 all well defined.
      def self.ec_emit_scalar_reduce(t, k_name, result_name, curve_n)
        t.push_big_int("_n_red", curve_n)
        t.raw_block([k_name, "_n_red"], result_name, lambda { |e|
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "drop"))
          e.call(make_stack_op(op: "over"))
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        })
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
        ec_emit_coord_canon_verify(t, "ax", "ay")

        # k' = k + 3n: guarantees bit 257 is set.
        # k in [1, n-1], so k+3n in [3n+1, 4n-1]. Since 3n > 2^257, bit 257
        # is always 1. Adding 3n (= 0 mod n) preserves the EC point: k*G = (k+3n)*G.
        #
        # "k in [1, n-1]" is a PRECONDITION the caller cannot enforce -- the
        # scalar is usually an unlock argument -- so reduce it first.
        curve_n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        t.to_top("_k")
        ec_emit_scalar_reduce(t, "_k", "_kr", curve_n)
        t.push_big_int("_n", curve_n)
        t.raw_block(["_kr", "_n"], "_kn", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
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
          # Only the final step can be handed two equal operands -- see
          # ec_build_jacobian_add_or_double_inline for why, and for what it
          # costs not to.
          if bit.zero?
            ec_build_jacobian_add_or_double_inline(add_emit, t)
          else
            ec_build_jacobian_add_affine_inline(add_emit, t)
          end
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
        ec_emit_coord_canon_verify(t, "_nx", "_ny")
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

        # CL-BUG-095: width. +ecOnCurve(G || 0xff)+ returned TRUE --
        # ec_decompose_point discarded the surplus byte, so 2^8 distinct blobs
        # all certified as the same point and a point's identity AS BYTES
        # stopped being unique. Clamp and remember the width, rather than abort,
        # because this is the predicate contracts are told to gate untrusted
        # points on and it must stay total; the flag is ANDed into the result at
        # the end.
        emit_point_length_gate(t, "_pt", 64, "_len_ok")

        ec_decompose_point(t, "_pt", "_x", "_y")

        # GAP-301: coordinate canonicity. `ec_decompose_point` BIN2NUMs each
        # coordinate as an unsigned value that may be >= p; the field arithmetic
        # below would silently reduce it mod p, so a non-canonical encoding of a
        # valid point would pass. Reject it: require x < p AND y < p (coordinates
        # are unsigned, so the 0 <= lower bound holds by construction). Combined
        # with the curve equation at the end via OP_BOOLAND so ecOnCurve still
        # returns a boolean.
        t.copy_to_top("_x", "_x_lt")
        ec_push_field_p(t, "_p_for_x")
        t.raw_block(["_x_lt", "_p_for_x"], "_x_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.copy_to_top("_y", "_y_lt")
        ec_push_field_p(t, "_p_for_y")
        t.raw_block(["_y_lt", "_p_for_y"], "_y_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_LESSTHAN")) })
        t.to_top("_x_canon")
        t.to_top("_y_canon")
        t.raw_block(["_x_canon", "_y_canon"], "_canon", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })

        # lhs = y^2
        ec_field_sqr(t, "_y", "_y2")

        # rhs = x^3 + 7
        t.copy_to_top("_x", "_x_copy")
        ec_field_sqr(t, "_x", "_x2")
        ec_field_mul(t, "_x2", "_x_copy", "_x3")
        t.push_int("_seven", 7)
        ec_field_add(t, "_x3", "_seven", "_rhs")

        # Compare curve equation
        t.to_top("_y2")
        t.to_top("_rhs")
        t.raw_block(["_y2", "_rhs"], "_curve_eq", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) })

        # on-curve = right width AND canonical AND curve-equation
        t.to_top("_canon")
        t.to_top("_curve_eq")
        t.raw_block(["_canon", "_curve_eq"], "_eq_ok", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })
        t.to_top("_len_ok")
        t.to_top("_eq_ok")
        t.raw_block(["_len_ok", "_eq_ok"], "_result", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_BOOLAND")) })
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
        # CL-BUG-095, and the reason this one is the sharpest edge of it: the
        # parity byte used to be taken from the blob's LAST byte (OP_SIZE 1
        # OP_SUB OP_SPLIT), not from a fixed offset. So appending one byte
        # FLIPPED THE SIGN of the compressed encoding -- the same 64-byte point
        # compressed to 02||x or 03||x at the caller's choice, and anything that
        # hashes a compressed pubkey (a P2PKH address, a commitment) became
        # forgeable between the two spellings. Two independent fixes, both kept:
        # the width is verified, and the parity byte is read from offset 31 of y
        # whatever the caller sent.
        emit_point_len_verify(emit, 64)
        # Split at 32: [x_bytes, y_bytes]
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        # Take y[31] at a FIXED offset: [x_bytes, y_head, y_last]
        emit.call(make_stack_op(op: "push", value: big_int_push(31)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_NIP")) # drop y_head
        # Stack: [x_bytes, last_byte]
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        emit.call(make_stack_op(op: "push", value: big_int_push(2)))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
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
      # R-156 -- verify that the script number on TOS is a FIELD ELEMENT, 0 <= v < p.
      # Leaves the value in place (OP_DUP feeds the check, OP_VERIFY consumes the
      # flag), so the caller's stack shape is unchanged.
      #
      # ecMakePoint converts each coordinate with `push 33, OP_NUM2BIN, push 32,
      # OP_SPLIT, OP_DROP`. NUM2BIN(33) writes a 33-byte little-endian SIGN-MAGNITUDE
      # script number, so byte 32 is exactly where the sign bit lives AND where any
      # bits >= 2^256 land -- and the split drops precisely that byte. The result was
      # an ecMakePoint that is NOT INJECTIVE:
      #
      #     ecMakePoint( 1n, y) == ecMakePoint(-1n, y)            sign discarded
      #     ecMakePoint( 1n, y) == ecMakePoint(1n + 2^256, y)     magnitude truncated
      #     ecMakePoint( x,  y) == ecMakePoint(x, -y)             and on the y half
      #
      # all three measured on @bsv/sdk's Spend. The y-half collision is the sharpest:
      # `ecMakePoint(x, 0n - y)` is how an author spells negation by hand, and it
      # silently produced (x, +y) -- the point being negated -- rather than (x, p-y).
      #
      # R-117's coordinate-canonicity gate does not cover this and cannot: the bytes
      # emitted for -1n are the perfectly canonical encoding of 1, so no downstream
      # consumer can tell. The aliasing happens before any Point exists.
      #
      # REJECT rather than reduce, for the reason R-117 gives: ecOnCurve answers "no"
      # to a coordinate outside [0, p), so reducing here would leave the constructor
      # and the predicate disagreeing about what a point is. Rejecting also restores
      # injectivity, which is the property the defect broke.
      #
      # OP_WITHIN(v, 0, p) is `0 <= v < p` in one opcode -- the same half-open bound
      # the `within` builtin exposes to contract authors.
      def self.ec_emit_field_element_verify(emit)
        emit.call(make_stack_op(op: "dup"))
        emit.call(make_stack_op(op: "push", value: big_int_push(0)))
        emit.call(make_stack_op(op: "push", value: big_int_push(EC_FIELD_P)))
        emit.call(make_stack_op(op: "opcode", code: "OP_WITHIN"))
        emit.call(make_stack_op(op: "opcode", code: "OP_VERIFY"))
      end

      def self.emit_ec_make_point(emit)
        # R-156: y must be a field element before its sign byte is dropped.
        ec_emit_field_element_verify(emit)
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
        # R-156: and so must x.
        ec_emit_field_element_verify(emit)
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
        # CL-BUG-095: a 32-byte blob used to SUCCEED here and return itself as x
        # -- the split at 32 left an empty tail that +drop+ happily removed.
        # ecPointY on the identical input already aborted, which is how the hole
        # survived: a short point looked "already rejected".
        emit_point_len_verify(emit, 64)
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
        emit_point_len_verify(emit, 64)
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
