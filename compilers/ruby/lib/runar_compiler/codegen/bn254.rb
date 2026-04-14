# frozen_string_literal: true

# BN254 codegen -- BN254 elliptic curve field arithmetic and G1 point
# operations for Bitcoin Script.
#
# Follows the ec.rb pattern: self-contained module imported by stack.rb.
# Uses a BN254Tracker (mirrors KBTracker/ECTracker) for named stack state
# tracking.
#
# BN254 parameters:
#   Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
#   Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
#   Curve:       y^2 = x^3 + 3
#   Generator:   G1 = (1, 2)
#
# Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
# Internal arithmetic uses Jacobian coordinates for scalar multiplication.
#
# Direct port of compilers/go/codegen/bn254.go

require "set"
require_relative "ec"

module RunarCompiler
  module Codegen
    module BN254
      # =================================================================
      # Constants
      # =================================================================

      # BN254 field prime p
      BN254_P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

      # BN254 curve order r
      BN254_R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

      # BN254 G1 generator x-coordinate
      BN254_GEN_X = 1

      # BN254 G1 generator y-coordinate
      BN254_GEN_Y = 2

      # p - 2, used for Fermat's little theorem modular inverse
      BN254_P_MINUS_2 = BN254_P - 2

      # =================================================================
      # StackOp / PushValue helpers (avoid circular dependency with stack.rb)
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
      # BN254Tracker -- named stack state tracker (mirrors ECTracker)
      # =================================================================

      class BN254Tracker
        # @return [Array<String>] named stack entries ("" for anonymous)
        attr_accessor :nm

        # @return [Boolean] true when the field prime is cached on the alt-stack
        attr_accessor :prime_cache_active

        # @param init [Array<String>] initial stack names
        # @param emit [Proc] callback receiving a StackOp hash
        def initialize(init, emit)
          @nm = init.dup
          @e = emit
          @prime_cache_active = false
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
          raise "BN254Tracker: '#{name}' not on stack #{@nm}"
        end

        # Push raw bytes onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [String] binary string of bytes
        def push_bytes(n, v)
          @e.call(BN254.make_stack_op(op: "push", value: BN254.make_push_value(kind: "bytes", bytes_val: v)))
          @nm.push(n)
        end

        # Push a big integer onto the stack.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_big_int(n, v)
          @e.call(BN254.make_stack_op(op: "push", value: BN254.make_push_value(kind: "bigint", big_int: v)))
          @nm.push(n)
        end

        # Push an integer onto the stack using big_int_push encoding.
        #
        # @param n [String] stack entry name
        # @param v [Integer]
        def push_int(n, v)
          @e.call(BN254.make_stack_op(op: "push", value: BN254.big_int_push(v)))
          @nm.push(n)
        end

        # Duplicate top of stack.
        #
        # @param n [String] name for the duplicate
        def dup(n)
          @e.call(BN254.make_stack_op(op: "dup"))
          @nm.push(n)
        end

        # Drop top of stack.
        def drop
          @e.call(BN254.make_stack_op(op: "drop"))
          @nm.pop if @nm.length > 0
        end

        # Remove second-to-top stack element.
        def nip
          @e.call(BN254.make_stack_op(op: "nip"))
          l = @nm.length
          if l >= 2
            @nm[l - 2..l - 1] = [@nm[l - 1]]
          end
        end

        # Copy second-to-top onto top.
        #
        # @param n [String] name for the copy
        def over(n)
          @e.call(BN254.make_stack_op(op: "over"))
          @nm.push(n)
        end

        # Swap top two stack elements.
        def swap
          @e.call(BN254.make_stack_op(op: "swap"))
          l = @nm.length
          if l >= 2
            @nm[l - 1], @nm[l - 2] = @nm[l - 2], @nm[l - 1]
          end
        end

        # Rotate top three stack elements.
        def rot
          @e.call(BN254.make_stack_op(op: "rot"))
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
          @e.call(BN254.make_stack_op(op: "opcode", code: code))
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
          @e.call(BN254.make_stack_op(op: "push", value: BN254.big_int_push(d)))
          @nm.push("")
          @e.call(BN254.make_stack_op(op: "roll", depth: d))
          @nm.pop
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
          @e.call(BN254.make_stack_op(op: "push", value: BN254.big_int_push(d)))
          @nm.push("")
          @e.call(BN254.make_stack_op(op: "pick", depth: d))
          @nm.pop
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
        # @param new_name [String] name for the copy
        def copy_to_top(name, new_name)
          pick(find_depth(name), new_name)
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
          consume.length.times { @nm.pop if @nm.length > 0 }
          fn.call(@e)
          @nm.push(produce) unless produce.empty?
        end

        # Push the BN254 field prime to the alt-stack for caching.
        #
        # Subsequent calls to bn254_field_mod will fetch the prime from the
        # alt-stack via OP_FROMALTSTACK/DUP/OP_TOALTSTACK (3 bytes) instead of
        # pushing the 34-byte literal, saving ~93 bytes per Fp mod.
        def push_prime_cache
          push_big_int("_pcache_p", BN254_P)
          op("OP_TOALTSTACK")
          @nm.pop if @nm.length > 0
          @prime_cache_active = true
        end

        # Remove the cached prime from the alt-stack.
        def pop_prime_cache
          op("OP_FROMALTSTACK")
          @nm.push("_pcache_cleanup")
          drop
          @prime_cache_active = false
        end
      end

      # =================================================================
      # Field arithmetic helpers
      # =================================================================

      # Push the BN254 field prime p onto the stack.
      #
      # @param t [BN254Tracker]
      # @param name [String]
      def self.bn254_push_field_p(t, name)
        t.push_big_int(name, BN254_P)
      end

      # Reduce TOS mod p, ensuring non-negative result.
      # Pattern: (a % p + p) % p
      #
      # When prime_cache_active is true, the field prime is fetched from the
      # alt-stack (OP_FROMALTSTACK/DUP/OP_TOALTSTACK) instead of being pushed
      # as a literal.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bn254_field_mod(t, a_name, result_name)
        t.to_top(a_name)
        if t.prime_cache_active
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            # [a, p] -> TUCK -> [p, a, p]
            e.call(make_stack_op(op: "opcode", code: "OP_TUCK"))
            # [p, a, p] -> MOD -> [p, a%p]
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
            # [p, a%p] -> OVER -> [p, a%p, p]
            e.call(make_stack_op(op: "over"))
            # [p, a%p, p] -> ADD -> [p, a%p+p]
            e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
            # [p, a%p+p] -> SWAP -> [a%p+p, p]
            e.call(make_stack_op(op: "swap"))
            # [a%p+p, p] -> MOD -> [(a%p+p)%p]
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name], result_name, fn)
        else
          bn254_push_field_p(t, "_fmod_p")
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_TUCK"))
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
            e.call(make_stack_op(op: "over"))
            e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
            e.call(make_stack_op(op: "swap"))
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name, "_fmod_p"], result_name, fn)
        end
      end

      # Reduce a non-negative value modulo p using a single OP_MOD.
      #
      # SAFETY: Only use when the input is guaranteed non-negative (e.g. after
      # OP_MUL of two non-negative values, or after OP_ADD of non-negative
      # values). After OP_SUB the result can be negative — use
      # bn254_field_mod instead.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bn254_field_mod_positive(t, a_name, result_name)
        t.to_top(a_name)
        if t.prime_cache_active
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            # [a, p] -> a % p (single mod, since a >= 0)
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name], result_name, fn)
        else
          bn254_push_field_p(t, "_fmodp_p")
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name, "_fmodp_p"], result_name, fn)
        end
      end

      # Compute (a + b) mod p.
      #
      # Both operands are non-negative so the sum is non-negative; the optimized
      # single-mod reduction is used.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bn254_field_add(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
        }
        t.raw_block([a_name, b_name], "_fadd_sum", fn)
        bn254_field_mod_positive(t, "_fadd_sum", result_name)
      end

      # Compute (a - b) mod p (non-negative).
      #
      # Computes (a - b + p) mod p. Works for a >= 0 and b in [0, p-1]. The
      # single OP_MOD handles the reduction since a - b + p is always
      # positive.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bn254_field_sub(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        if t.prime_cache_active
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_SUB")) # [diff]
            e.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            # [diff, p] -> TUCK -> [p, diff, p]
            e.call(make_stack_op(op: "opcode", code: "OP_TUCK"))
            # [p, diff, p] -> ADD -> [p, diff+p]
            e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
            # [p, diff+p] -> SWAP -> [diff+p, p]
            e.call(make_stack_op(op: "swap"))
            # [diff+p, p] -> MOD -> [(diff+p)%p]
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name, b_name], result_name, fn)
        else
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
          }
          t.raw_block([a_name, b_name], "_fsub_diff", fn)
          bn254_field_mod(t, "_fsub_diff", result_name)
        end
      end

      # Compute (a * b) mod p.
      #
      # Both operands are non-negative (field elements or unreduced
      # sums/products), so the optimized single-mod reduction is used.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param b_name [String]
      # @param result_name [String]
      def self.bn254_field_mul(t, a_name, b_name, result_name)
        t.to_top(a_name)
        t.to_top(b_name)
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
        }
        t.raw_block([a_name, b_name], "_fmul_prod", fn)
        bn254_field_mod_positive(t, "_fmul_prod", result_name)
      end

      # Compute (a * a) mod p.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bn254_field_sqr(t, a_name, result_name)
        t.copy_to_top(a_name, "_fsqr_copy")
        bn254_field_mul(t, a_name, "_fsqr_copy", result_name)
      end

      # Compute (p - a) mod p.
      #
      # Since a is a field element in [0, p-1], p - a is always in [1, p].
      # Fetches p once and DUPs for reuse: one copy for the subtraction, one
      # for the mod.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bn254_field_neg(t, a_name, result_name)
        t.to_top(a_name)
        if t.prime_cache_active
          fn = ->(e) {
            # [a]
            e.call(make_stack_op(op: "opcode", code: "OP_FROMALTSTACK"))
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(make_stack_op(op: "opcode", code: "OP_TOALTSTACK"))
            # [a, p] -> DUP -> [a, p, p]
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            # [a, p, p] -> ROT -> [p, p, a]
            e.call(make_stack_op(op: "rot"))
            # [p, p, a] -> SUB -> [p, p-a]
            e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
            # [p, p-a] -> SWAP -> [p-a, p]
            e.call(make_stack_op(op: "swap"))
            # [p-a, p] -> MOD -> [(p-a)%p]
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name], result_name, fn)
        else
          bn254_push_field_p(t, "_fneg_p")
          fn = ->(e) {
            e.call(make_stack_op(op: "opcode", code: "OP_DUP"))
            e.call(make_stack_op(op: "rot"))
            e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
            e.call(make_stack_op(op: "swap"))
            e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          }
          t.raw_block([a_name, "_fneg_p"], result_name, fn)
        end
      end

      # Compute a^(p-2) mod p via square-and-multiply (Fermat's little
      # theorem).
      #
      # BN254 p is a 254-bit prime, so p-2 is also 254 bits with MSB at
      # bit 253. We handle the MSB by initializing result = a (equivalent to
      # processing bit 253 with an empty accumulator), then loop over bits
      # 252 down to 0. That gives 253 squarings plus one conditional multiply
      # per set bit in positions 252..0.
      #
      # NOTE: this is not constant-time. Since p-2 is a public constant no
      # secret information is leaked.
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param result_name [String]
      def self.bn254_field_inv(t, a_name, result_name)
        # result = a implicitly handles bit 253 (the MSB of p-2, always set)
        t.copy_to_top(a_name, "_inv_r")

        # Process bits 252 down to 0 (253 iterations, one squaring each)
        p_minus_2 = BN254_P_MINUS_2
        252.downto(0) do |i|
          # Always square
          bn254_field_sqr(t, "_inv_r", "_inv_r2")
          t.rename("_inv_r")

          # Multiply if bit is set
          if (p_minus_2 >> i) & 1 == 1
            t.copy_to_top(a_name, "_inv_a")
            bn254_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")
          end
        end

        # Clean up original input and rename result
        t.to_top(a_name)
        t.drop
        t.to_top("_inv_r")
        t.rename(result_name)
      end

      # Compute (a * c) mod p where c is a small constant.
      #
      # Uses OP_2MUL when c == 2 (single opcode, no push needed).
      #
      # @param t [BN254Tracker]
      # @param a_name [String]
      # @param c [Integer]
      # @param result_name [String]
      def self.bn254_field_mul_const(t, a_name, c, result_name)
        t.to_top(a_name)
        fn = ->(e) {
          if c == 2
            e.call(make_stack_op(op: "opcode", code: "OP_2MUL"))
          else
            e.call(make_stack_op(op: "push", value: big_int_push(c)))
            e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
          end
        }
        t.raw_block([a_name], "_bn_mc", fn)
        bn254_field_mod_positive(t, "_bn_mc", result_name)
      end

      # =================================================================
      # Point decompose / compose
      # =================================================================

      # Decompose a 64-byte Point into (x_num, y_num) on stack.
      #
      # Consumes point_name, produces x_name and y_name.
      #
      # @param t [BN254Tracker]
      # @param point_name [String]
      # @param x_name [String]
      # @param y_name [String]
      def self.bn254_decompose_point(t, point_name, x_name, y_name)
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
        # Reverse from BE to LE, append 0x00 sign byte to ensure unsigned,
        # then BIN2NUM.
        convert_y = ->(e) {
          EC.ec_emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_yb"], y_name, convert_y)

        # Convert x_bytes to num
        t.to_top("_dp_xb")
        convert_x = ->(e) {
          EC.ec_emit_reverse32(e)
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
      # IMPORTANT: Callers must ensure x and y are valid field elements in
      # [0, p-1]. This function does not validate input range. Passing values
      # >= p will produce incorrect big-endian encodings.
      #
      # @param t [BN254Tracker]
      # @param x_name [String]
      # @param y_name [String]
      # @param result_name [String]
      def self.bn254_compose_point(t, x_name, y_name, result_name)
        # Convert x to 32-byte big-endian
        t.to_top(x_name)
        convert_x = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(33)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          # Drop the sign byte (last byte) -- split at 32, keep left
          e.call(make_stack_op(op: "push", value: big_int_push(32)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          EC.ec_emit_reverse32(e)
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
          EC.ec_emit_reverse32(e)
        }
        t.raw_block([y_name], "_cp_yb", convert_y)

        # Cat: x_be || y_be (x is below y after the two to_top calls)
        t.to_top("_cp_xb")
        t.to_top("_cp_yb")
        cat_fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
        }
        t.raw_block(["_cp_xb", "_cp_yb"], result_name, cat_fn)
      end

      # =================================================================
      # Affine point addition (for bn254_g1_add)
      # =================================================================

      # Perform affine point addition on BN254 G1.
      #
      # Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four
      # inputs.
      #
      # Uses the unified slope formula
      #
      #   s = (px^2 + px*qx + qx^2) / (py + qy)
      #
      # which works for both the addition case (P != Q) and the doubling case
      # (P == Q) on y^2 = x^3 + b. The standard chord formula
      # s = (qy-py)/(qx-px) divides by zero when P == Q; the unified form is
      # mathematically equivalent for distinct points (multiply numerator and
      # denominator by (qx-px) and use the curve equation y^2 = x^3 + b) and
      # collapses to 3*px^2/(2*py) when P == Q, which is the correct doubling
      # slope.
      #
      # The only input that still fails is P == -Q (py + qy == 0, group
      # identity), which is out of scope for Groth16 verifier usage.
      #
      # @param t [BN254Tracker]
      def self.bn254_g1_affine_add(t)
        # s_num = px^2 + px*qx + qx^2
        t.copy_to_top("px", "_px_sq_in")
        bn254_field_sqr(t, "_px_sq_in", "_px_sq")
        t.copy_to_top("px", "_px_m")
        t.copy_to_top("qx", "_qx_m")
        bn254_field_mul(t, "_px_m", "_qx_m", "_px_qx")
        t.copy_to_top("qx", "_qx_sq_in")
        bn254_field_sqr(t, "_qx_sq_in", "_qx_sq")
        bn254_field_add(t, "_px_sq", "_px_qx", "_s_num_tmp")
        bn254_field_add(t, "_s_num_tmp", "_qx_sq", "_s_num")

        # s_den = py + qy
        t.copy_to_top("py", "_py_a")
        t.copy_to_top("qy", "_qy_a")
        bn254_field_add(t, "_py_a", "_qy_a", "_s_den")

        # s = s_num / s_den mod p
        bn254_field_inv(t, "_s_den", "_s_den_inv")
        bn254_field_mul(t, "_s_num", "_s_den_inv", "_s")

        # rx = s^2 - px - qx mod p
        t.copy_to_top("_s", "_s_keep")
        bn254_field_sqr(t, "_s", "_s2")
        t.copy_to_top("px", "_px2")
        bn254_field_sub(t, "_s2", "_px2", "_rx1")
        t.copy_to_top("qx", "_qx2")
        bn254_field_sub(t, "_rx1", "_qx2", "rx")

        # ry = s * (px - rx) - py mod p
        t.copy_to_top("px", "_px3")
        t.copy_to_top("rx", "_rx2")
        bn254_field_sub(t, "_px3", "_rx2", "_px_rx")
        bn254_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
        t.copy_to_top("py", "_py2")
        bn254_field_sub(t, "_s_px_rx", "_py2", "ry")

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
      # Jacobian point operations (for bn254_g1_scalar_mul)
      # =================================================================

      # Perform Jacobian point doubling (a=0 for BN254).
      #
      # Expects jx, jy, jz on tracker. Replaces with updated values.
      #
      # Formulas (a=0 since y^2 = x^3 + b):
      #   A  = Y^2
      #   B  = 4*X*A
      #   C  = 8*A^2
      #   D  = 3*X^2  (a=0, so 3*X^2 + a*Z^4 simplifies to 3*X^2)
      #   X' = D^2 - 2*B
      #   Y' = D*(B - X') - C
      #   Z' = 2*Y*Z
      #
      # @param t [BN254Tracker]
      def self.bn254_g1_jacobian_double(t)
        # Save copies of jx, jy, jz for later use
        t.copy_to_top("jy", "_jy_save")
        t.copy_to_top("jx", "_jx_save")
        t.copy_to_top("jz", "_jz_save")

        # A = jy^2
        bn254_field_sqr(t, "jy", "_A")

        # B = 4 * jx * A
        t.copy_to_top("_A", "_A_save")
        bn254_field_mul(t, "jx", "_A", "_xA")
        t.push_int("_four", 4)
        bn254_field_mul(t, "_xA", "_four", "_B")

        # C = 8 * A^2
        bn254_field_sqr(t, "_A_save", "_A2")
        t.push_int("_eight", 8)
        bn254_field_mul(t, "_A2", "_eight", "_C")

        # D = 3 * X^2
        bn254_field_sqr(t, "_jx_save", "_x2")
        t.push_int("_three", 3)
        bn254_field_mul(t, "_x2", "_three", "_D")

        # nx = D^2 - 2*B
        t.copy_to_top("_D", "_D_save")
        t.copy_to_top("_B", "_B_save")
        bn254_field_sqr(t, "_D", "_D2")
        t.copy_to_top("_B", "_B1")
        bn254_field_mul_const(t, "_B1", 2, "_2B")
        bn254_field_sub(t, "_D2", "_2B", "_nx")

        # ny = D*(B - nx) - C
        t.copy_to_top("_nx", "_nx_copy")
        bn254_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
        bn254_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
        bn254_field_sub(t, "_D_B_nx", "_C", "_ny")

        # nz = 2 * Y * Z
        bn254_field_mul(t, "_jy_save", "_jz_save", "_yz")
        bn254_field_mul_const(t, "_yz", 2, "_nz")

        # Clean up leftovers: _B and old jz
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
      # @param t [BN254Tracker]
      # @param rx_name [String]
      # @param ry_name [String]
      def self.bn254_g1_jacobian_to_affine(t, rx_name, ry_name)
        bn254_field_inv(t, "jz", "_zinv")
        t.copy_to_top("_zinv", "_zinv_keep")
        bn254_field_sqr(t, "_zinv", "_zinv2")
        t.copy_to_top("_zinv2", "_zinv2_keep")
        bn254_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3")
        bn254_field_mul(t, "jx", "_zinv2_keep", rx_name)
        bn254_field_mul(t, "jy", "_zinv3", ry_name)
      end

      # =================================================================
      # Jacobian mixed addition (P_jacobian + Q_affine)
      # =================================================================

      # Emit the standard Jacobian mixed-add sequence assuming the doubling
      # case has already been excluded by the caller.
      #
      # Consumes jx, jy, jz on the tracker (the affine base point ax, ay is
      # read via copy-to-top) and produces replacement jx, jy, jz.
      #
      # WARNING: this function fails (H = 0 in the chord formula) when the
      # Jacobian accumulator equals the affine base point in affine form.
      # Callers must guard against that case; see
      # bn254_build_jacobian_add_affine_inline for the complete doubling-safe
      # wrapper used by scalar multiplication.
      #
      # @param it [BN254Tracker]
      def self.bn254_build_jacobian_add_affine_standard(it)
        # Save copies of values that get consumed but are needed later
        it.copy_to_top("jz", "_jz_for_z1cu") # consumed by Z1sq, needed for Z1cu
        it.copy_to_top("jz", "_jz_for_z3")   # needed for Z3
        it.copy_to_top("jy", "_jy_for_y3")   # consumed by R, needed for Y3
        it.copy_to_top("jx", "_jx_for_u1h2") # consumed by H, needed for U1H2

        # Z1sq = jz^2
        bn254_field_sqr(it, "jz", "_Z1sq")

        # Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
        it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
        bn254_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

        # U2 = ax * Z1sq_for_u2
        it.copy_to_top("ax", "_ax_c")
        bn254_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

        # S2 = ay * Z1cu
        it.copy_to_top("ay", "_ay_c")
        bn254_field_mul(it, "_ay_c", "_Z1cu", "_S2")

        # H = U2 - jx
        bn254_field_sub(it, "_U2", "jx", "_H")

        # R = S2 - jy
        bn254_field_sub(it, "_S2", "jy", "_R")

        # Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
        it.copy_to_top("_H", "_H_for_h3")
        it.copy_to_top("_H", "_H_for_z3")

        # H2 = H^2
        bn254_field_sqr(it, "_H", "_H2")

        # Save H2 for U1H2
        it.copy_to_top("_H2", "_H2_for_u1h2")

        # H3 = H_for_h3 * H2
        bn254_field_mul(it, "_H_for_h3", "_H2", "_H3")

        # U1H2 = _jx_for_u1h2 * H2_for_u1h2
        bn254_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

        # Save R, U1H2, H3 for Y3 computation
        it.copy_to_top("_R", "_R_for_y3")
        it.copy_to_top("_U1H2", "_U1H2_for_y3")
        it.copy_to_top("_H3", "_H3_for_y3")

        # X3 = R^2 - H3 - 2*U1H2
        bn254_field_sqr(it, "_R", "_R2")
        bn254_field_sub(it, "_R2", "_H3", "_x3_tmp")
        bn254_field_mul_const(it, "_U1H2", 2, "_2U1H2")
        bn254_field_sub(it, "_x3_tmp", "_2U1H2", "_X3")

        # Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
        it.copy_to_top("_X3", "_X3_c")
        bn254_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
        bn254_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
        bn254_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
        bn254_field_sub(it, "_r_tmp", "_jy_h3", "_Y3")

        # Z3 = _jz_for_z3 * _H_for_z3
        bn254_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

        # Rename results to jx/jy/jz
        it.to_top("_X3")
        it.rename("jx")
        it.to_top("_Y3")
        it.rename("jy")
        it.to_top("_Z3")
        it.rename("jz")
      end

      # Build doubling-safe Jacobian mixed-add ops for use inside OP_IF.
      #
      # Stack layout: [..., ax, ay, _k, jx, jy, jz]
      # After:        [..., ax, ay, _k, jx', jy', jz']
      #
      # The standard Jacobian mixed-add formula divides by H = ax*jz^2 - jx,
      # which is 0 when the accumulator's affine image equals the base point
      # -- a deterministic trajectory for certain scalars (k=2, etc.). To
      # handle the doubling case, we check H == 0 at runtime and delegate to
      # Jacobian doubling of (jx, jy, jz) when it fires. The standard mixed-add
      # runs otherwise.
      #
      # The negation case (H == 0 with R != 0, i.e. acc = -base) produces
      # incorrect results, but is cryptographically unreachable for valid
      # Groth16 public inputs.
      #
      # @param e [Proc] emit callback
      # @param t [BN254Tracker]
      def self.bn254_build_jacobian_add_affine_inline(e, t)
        # Create inner tracker with cloned stack state
        it = BN254Tracker.new(t.nm.dup, e)
        # Propagate prime cache state: the cached prime on the alt-stack is
        # accessible within OP_IF branches since alt-stack persists across
        # IF/ELSE/ENDIF boundaries.
        it.prime_cache_active = t.prime_cache_active

        # ------------------------------------------------------------------
        # Doubling-case detection: H = ax*jz^2 - jx == 0 ?
        # ------------------------------------------------------------------
        # Compute U2 = ax * jz^2 without consuming jx, jy, or jz, then
        # compare against a fresh copy of jx. Consumes only the copies.
        it.copy_to_top("jz", "_jz_chk_in")
        bn254_field_sqr(it, "_jz_chk_in", "_jz_chk_sq")
        it.copy_to_top("ax", "_ax_chk_copy")
        bn254_field_mul(it, "_ax_chk_copy", "_jz_chk_sq", "_u2_chk")
        it.copy_to_top("jx", "_jx_chk_copy")
        eq_fn = ->(ee) {
          ee.call(make_stack_op(op: "opcode", code: "OP_NUMEQUAL"))
        }
        it.raw_block(["_u2_chk", "_jx_chk_copy"], "_h_is_zero", eq_fn)

        # Move _h_is_zero to top so OP_IF can consume it.
        it.to_top("_h_is_zero")
        it.nm.pop # consumed by IF

        # ------------------------------------------------------------------
        # Gather doubling-branch ops
        # ------------------------------------------------------------------
        doubling_ops = []
        doubling_emit = ->(op) { doubling_ops.push(op) }
        doubling_tracker = BN254Tracker.new(it.nm.dup, doubling_emit)
        doubling_tracker.prime_cache_active = it.prime_cache_active
        bn254_g1_jacobian_double(doubling_tracker)

        # ------------------------------------------------------------------
        # Gather standard-add-branch ops
        # ------------------------------------------------------------------
        add_ops = []
        add_emit = ->(op) { add_ops.push(op) }
        add_tracker = BN254Tracker.new(it.nm.dup, add_emit)
        add_tracker.prime_cache_active = it.prime_cache_active
        bn254_build_jacobian_add_affine_standard(add_tracker)

        # Both branches leave (jx, jy, jz) replacing the originals with the
        # same stack layout.
        e.call(make_stack_op(op: "if", then: doubling_ops, else_ops: add_ops))
        it.nm = doubling_tracker.nm
      end

      # =================================================================
      # G1 point negation
      # =================================================================

      # Negate a point: (x, p - y).
      #
      # @param t [BN254Tracker]
      # @param point_name [String]
      # @param result_name [String]
      def self.bn254_g1_negate(t, point_name, result_name)
        bn254_decompose_point(t, point_name, "_nx", "_ny")
        # Use bn254_field_neg which already handles prime caching
        bn254_field_neg(t, "_ny", "_neg_y")
        bn254_compose_point(t, "_nx", "_neg_y", result_name)
      end

      # =================================================================
      # Public emit functions -- entry points called from stack.rb
      # =================================================================

      # BN254 field addition.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a + b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_field_add(emit)
        t = BN254Tracker.new(%w[a b], emit)
        t.push_prime_cache
        bn254_field_add(t, "a", "b", "result")
        t.pop_prime_cache
      end

      # BN254 field subtraction.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a - b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_field_sub(emit)
        t = BN254Tracker.new(%w[a b], emit)
        t.push_prime_cache
        bn254_field_sub(t, "a", "b", "result")
        t.pop_prime_cache
      end

      # BN254 field multiplication.
      # Stack in: [..., a, b] (b on top)
      # Stack out: [..., (a * b) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_field_mul(emit)
        t = BN254Tracker.new(%w[a b], emit)
        t.push_prime_cache
        bn254_field_mul(t, "a", "b", "result")
        t.pop_prime_cache
      end

      # BN254 field multiplicative inverse.
      # Stack in: [..., a]
      # Stack out: [..., a^(p-2) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_field_inv(emit)
        t = BN254Tracker.new(["a"], emit)
        t.push_prime_cache
        bn254_field_inv(t, "a", "result")
        t.pop_prime_cache
      end

      # BN254 field negation.
      # Stack in: [..., a]
      # Stack out: [..., (p - a) mod p]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_field_neg(emit)
        t = BN254Tracker.new(["a"], emit)
        t.push_prime_cache
        bn254_field_neg(t, "a", "result")
        t.pop_prime_cache
      end

      # Add two BN254 G1 points.
      # Stack in: [point_a, point_b] (b on top)
      # Stack out: [result_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_g1_add(emit)
        t = BN254Tracker.new(%w[_pa _pb], emit)
        t.push_prime_cache
        bn254_decompose_point(t, "_pa", "px", "py")
        bn254_decompose_point(t, "_pb", "qx", "qy")
        bn254_g1_affine_add(t)
        bn254_compose_point(t, "rx", "ry", "_result")
        t.pop_prime_cache
      end

      # Scalar multiplication P * k on BN254 G1.
      # Stack in: [point, scalar] (scalar on top)
      # Stack out: [result_point]
      #
      # Uses 255-iteration double-and-add with Jacobian coordinates.
      # k' = k + 3*r guarantees bit 255 is set (r is the curve order).
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_g1_scalar_mul(emit)
        t = BN254Tracker.new(%w[_pt _k], emit)
        t.push_prime_cache
        # Decompose to affine base point
        bn254_decompose_point(t, "_pt", "ax", "ay")

        # k' = k + 3r: guarantees bit 255 is set.
        # k in [1, r-1], so k+3r in [3r+1, 4r-1]. Since 3r > 2^255, bit 255
        # is always 1. Adding 3r (= 0 mod r) preserves the EC point:
        # k*G = (k+3r)*G.
        t.to_top("_k")
        t.push_big_int("_r1", BN254_R)
        add_fn = ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) }
        t.raw_block(%w[_k _r1], "_kr1", add_fn)
        t.push_big_int("_r2", BN254_R)
        t.raw_block(%w[_kr1 _r2], "_kr2", add_fn)
        t.push_big_int("_r3", BN254_R)
        t.raw_block(%w[_kr2 _r3], "_kr3", add_fn)
        t.rename("_k")

        # Init accumulator = P (bit 255 of k+3r is always 1)
        t.copy_to_top("ax", "jx")
        t.copy_to_top("ay", "jy")
        t.push_int("jz", 1)

        # 255 iterations: bits 254 down to 0
        254.downto(0) do |bit|
          # Double accumulator
          bn254_g1_jacobian_double(t)

          # Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
          t.copy_to_top("_k", "_k_copy")
          if bit == 1
            # Single-bit shift: OP_2DIV (no push needed)
            shift_fn = ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_2DIV")) }
            t.raw_block(["_k_copy"], "_shifted", shift_fn)
          elsif bit > 1
            # Multi-bit shift: push shift amount, OP_RSHIFTNUM
            t.push_int("_shift", bit)
            shift_fn = ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_RSHIFTNUM")) }
            t.raw_block(%w[_k_copy _shift], "_shifted", shift_fn)
          else
            t.rename("_shifted")
          end
          t.push_int("_two", 2)
          mod_fn = ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) }
          t.raw_block(%w[_shifted _two], "_bit", mod_fn)

          # Move _bit to TOS and remove from tracker BEFORE generating add ops,
          # because OP_IF consumes _bit and the add ops run with _bit already
          # gone.
          t.to_top("_bit")
          t.nm.pop # _bit consumed by IF
          add_ops = []
          add_emit = ->(op) { add_ops.push(op) }
          bn254_build_jacobian_add_affine_inline(add_emit, t)
          emit.call(make_stack_op(op: "if", then: add_ops, else_ops: []))
        end

        # Convert Jacobian to affine
        bn254_g1_jacobian_to_affine(t, "_rx", "_ry")

        # Clean up base point and scalar
        t.to_top("ax")
        t.drop
        t.to_top("ay")
        t.drop
        t.to_top("_k")
        t.drop

        # Compose result
        bn254_compose_point(t, "_rx", "_ry", "_result")
        t.pop_prime_cache
      end

      # Negate a BN254 G1 point (x, p - y).
      # Stack in: [point]
      # Stack out: [negated_point]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_g1_negate(emit)
        t = BN254Tracker.new(["_pt"], emit)
        t.push_prime_cache
        bn254_g1_negate(t, "_pt", "_result")
        t.pop_prime_cache
      end

      # Check if point is on BN254 G1 (y^2 = x^3 + 3 mod p).
      # Stack in: [point]
      # Stack out: [boolean]
      #
      # @param emit [Proc] callback receiving a StackOp hash
      def self.emit_bn254_g1_on_curve(emit)
        t = BN254Tracker.new(["_pt"], emit)
        t.push_prime_cache
        bn254_decompose_point(t, "_pt", "_x", "_y")

        # lhs = y^2
        bn254_field_sqr(t, "_y", "_y2")

        # rhs = x^3 + 3
        t.copy_to_top("_x", "_x_copy")
        bn254_field_sqr(t, "_x", "_x2")
        bn254_field_mul(t, "_x2", "_x_copy", "_x3")
        t.push_int("_three", 3) # b = 3 for BN254
        bn254_field_add(t, "_x3", "_three", "_rhs")

        # Compare
        t.to_top("_y2")
        t.to_top("_rhs")
        eq_fn = ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) }
        t.raw_block(%w[_y2 _rhs], "_result", eq_fn)
        t.pop_prime_cache
      end

      # =================================================================
      # Dispatch
      # =================================================================

      BN254_DISPATCH = {
        "bn254FieldAdd"    => method(:emit_bn254_field_add),
        "bn254FieldSub"    => method(:emit_bn254_field_sub),
        "bn254FieldMul"    => method(:emit_bn254_field_mul),
        "bn254FieldInv"    => method(:emit_bn254_field_inv),
        "bn254FieldNeg"    => method(:emit_bn254_field_neg),
        "bn254G1Add"       => method(:emit_bn254_g1_add),
        "bn254G1ScalarMul" => method(:emit_bn254_g1_scalar_mul),
        "bn254G1Negate"    => method(:emit_bn254_g1_negate),
        "bn254G1OnCurve"   => method(:emit_bn254_g1_on_curve),
      }.freeze

      # BN254 builtin function names.
      BN254_BUILTIN_NAMES = Set.new(%w[
        bn254FieldAdd bn254FieldSub bn254FieldMul bn254FieldInv bn254FieldNeg
        bn254G1Add bn254G1ScalarMul bn254G1Negate bn254G1OnCurve
      ]).freeze

      # Return true if +name+ is a BN254 builtin.
      #
      # @param name [String]
      # @return [Boolean]
      def self.bn254_builtin?(name)
        BN254_BUILTIN_NAMES.include?(name)
      end

      # Call the appropriate BN254 emit function for func_name.
      #
      # @param func_name [String]
      # @param emit [Proc] callback receiving a StackOp hash
      # @raise [RuntimeError] if func_name is not a known BN254 builtin
      def self.dispatch_bn254_builtin(func_name, emit)
        fn = BN254_DISPATCH[func_name]
        raise "unknown BN254 builtin: #{func_name}" if fn.nil?
        fn.call(emit)
      end
    end
  end
end
