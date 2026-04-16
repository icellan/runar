# frozen_string_literal: true

# P-256 / P-384 codegen -- NIST elliptic curve operations for Bitcoin Script.
#
# Follows the same pattern as ec.rb (secp256k1). Uses ECTracker for
# named stack state tracking, but with different field primes, curve orders,
# and generator points.
#
# Point representation:
#   P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
#   P-384: 96 bytes (x[48] || y[48], big-endian unsigned)
#
# Key difference from secp256k1: curve parameter a = -3 (not 0), which gives
# an optimized Jacobian doubling formula.
#
# Direct port of compilers/go/codegen/p256_p384.go

require_relative "ec"

module RunarCompiler
  module Codegen
    module NISTEC
      # =================================================================
      # P-256 constants (secp256r1 / NIST P-256)
      # =================================================================

      P256_P        = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
      P256_P_MINUS2 = P256_P - 2
      P256_B        = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
      P256_N        = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
      P256_N_MINUS2 = P256_N - 2
      P256_GX       = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
      P256_GY       = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
      # sqrtExp = (p + 1) / 4
      P256_SQRT_EXP = (P256_P + 1) >> 2

      # =================================================================
      # P-384 constants (secp384r1 / NIST P-384)
      # =================================================================

      P384_P        = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
      P384_P_MINUS2 = P384_P - 2
      P384_B        = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef
      P384_N        = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
      P384_N_MINUS2 = P384_N - 2
      P384_GX       = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
      P384_GY       = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
      # sqrtExp = (p + 1) / 4
      P384_SQRT_EXP = (P384_P + 1) >> 2

      # =================================================================
      # Curve parameter structs
      # =================================================================

      NistCurveParams = Struct.new(:field_p, :field_p_minus2, :coord_bytes, :reverse_bytes_fn, keyword_init: true)
      NistGroupParams = Struct.new(:n, :n_minus2, keyword_init: true)

      P256_CURVE = NistCurveParams.new(
        field_p:         P256_P,
        field_p_minus2:  P256_P_MINUS2,
        coord_bytes:     32,
        reverse_bytes_fn: ->(e) { NISTEC.emit_reverse32(e) }
      )

      P384_CURVE = NistCurveParams.new(
        field_p:         P384_P,
        field_p_minus2:  P384_P_MINUS2,
        coord_bytes:     48,
        reverse_bytes_fn: ->(e) { NISTEC.emit_reverse48(e) }
      )

      P256_GROUP = NistGroupParams.new(n: P256_N, n_minus2: P256_N_MINUS2)
      P384_GROUP = NistGroupParams.new(n: P384_N, n_minus2: P384_N_MINUS2)

      # =================================================================
      # Helper: convert integer to N-byte big-endian binary string
      # =================================================================

      def self.bigint_to_n_bytes(n, size)
        hex = n.to_s(16).rjust(size * 2, "0")
        [hex].pack("H*")
      end

      # =================================================================
      # Helper: bit length of an integer
      # =================================================================

      def self.bit_len(n)
        return 0 if n == 0
        n.bit_length
      end

      # =================================================================
      # StackOp / PushValue helpers (reuse from EC module)
      # =================================================================

      def self.make_stack_op(**kwargs)
        EC.make_stack_op(**kwargs)
      end

      def self.make_push_value(**kwargs)
        EC.make_push_value(**kwargs)
      end

      def self.big_int_push(n)
        EC.big_int_push(n)
      end

      # =================================================================
      # Byte reversal for 32 bytes (P-256) -- reuse from EC
      # =================================================================

      def self.emit_reverse32(e)
        EC.ec_emit_reverse32(e)
      end

      # =================================================================
      # Byte reversal for 48 bytes (P-384)
      # =================================================================

      def self.emit_reverse48(e)
        e.call(make_stack_op(op: "opcode", code: "OP_0"))
        e.call(make_stack_op(op: "swap"))
        48.times do
          e.call(make_stack_op(op: "push", value: big_int_push(1)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "swap"))
        end
        e.call(make_stack_op(op: "drop"))
      end

      # =================================================================
      # Generic curve field arithmetic (parameterized by prime)
      # =================================================================

      def self.c_push_field_p(t, name, c)
        t.push_big_int(name, c.field_p)
      end

      def self.c_field_mod(t, a_name, result_name, c)
        t.to_top(a_name)
        c_push_field_p(t, "_fmod_p", c)
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "drop"))
          e.call(make_stack_op(op: "over"))
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        }
        t.raw_block([a_name, "_fmod_p"], result_name, fn)
      end

      def self.c_field_add(t, a_name, b_name, result_name, c)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fadd_sum", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        c_field_mod(t, "_fadd_sum", result_name, c)
      end

      def self.c_field_sub(t, a_name, b_name, result_name, c)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fsub_diff", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_SUB")) })
        c_field_mod(t, "_fsub_diff", result_name, c)
      end

      def self.c_field_mul(t, a_name, b_name, result_name, c)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_fmul_prod", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        c_field_mod(t, "_fmul_prod", result_name, c)
      end

      def self.c_field_mul_const(t, a_name, cv, result_name, c)
        t.to_top(a_name)
        t.raw_block([a_name], "_fmc_prod", ->(e) {
          if cv == 2
            e.call(make_stack_op(op: "opcode", code: "OP_2MUL"))
          else
            e.call(make_stack_op(op: "push", value: big_int_push(cv)))
            e.call(make_stack_op(op: "opcode", code: "OP_MUL"))
          end
        })
        c_field_mod(t, "_fmc_prod", result_name, c)
      end

      def self.c_field_sqr(t, a_name, result_name, c)
        t.copy_to_top(a_name, "_fsqr_copy")
        c_field_mul(t, a_name, "_fsqr_copy", result_name, c)
      end

      # Generic square-and-multiply inversion: a^(p-2) mod p
      def self.c_field_inv(t, a_name, result_name, c)
        exp = c.field_p_minus2
        bits = bit_len(exp)

        t.copy_to_top(a_name, "_inv_r")

        (bits - 2).downto(0) do |i|
          c_field_sqr(t, "_inv_r", "_inv_r2", c)
          t.rename("_inv_r")
          if exp[i] == 1
            t.copy_to_top(a_name, "_inv_a")
            c_field_mul(t, "_inv_r", "_inv_a", "_inv_m", c)
            t.rename("_inv_r")
          end
        end

        t.to_top(a_name)
        t.drop
        t.to_top("_inv_r")
        t.rename(result_name)
      end

      # =================================================================
      # Group-order arithmetic (for ECDSA: mod n operations)
      # =================================================================

      def self.c_push_group_n(t, name, g)
        t.push_big_int(name, g.n)
      end

      def self.c_group_mod(t, a_name, result_name, g)
        t.to_top(a_name)
        c_push_group_n(t, "_gmod_n", g)
        fn = ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_2DUP"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
          e.call(make_stack_op(op: "rot"))
          e.call(make_stack_op(op: "drop"))
          e.call(make_stack_op(op: "over"))
          e.call(make_stack_op(op: "opcode", code: "OP_ADD"))
          e.call(make_stack_op(op: "swap"))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        }
        t.raw_block([a_name, "_gmod_n"], result_name, fn)
      end

      def self.c_group_mul(t, a_name, b_name, result_name, g)
        t.to_top(a_name)
        t.to_top(b_name)
        t.raw_block([a_name, b_name], "_gmul_prod", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MUL")) })
        c_group_mod(t, "_gmul_prod", result_name, g)
      end

      # a^(n-2) mod n via square-and-multiply
      def self.c_group_inv(t, a_name, result_name, g)
        exp = g.n_minus2
        bits = bit_len(exp)

        t.copy_to_top(a_name, "_ginv_r")

        (bits - 2).downto(0) do |i|
          t.copy_to_top("_ginv_r", "_ginv_sq_copy")
          c_group_mul(t, "_ginv_r", "_ginv_sq_copy", "_ginv_sq", g)
          t.rename("_ginv_r")
          if exp[i] == 1
            t.copy_to_top(a_name, "_ginv_a")
            c_group_mul(t, "_ginv_r", "_ginv_a", "_ginv_m", g)
            t.rename("_ginv_r")
          end
        end

        t.to_top(a_name)
        t.drop
        t.to_top("_ginv_r")
        t.rename(result_name)
      end

      # =================================================================
      # Point decompose / compose (parameterized by coordinate byte size)
      # =================================================================

      def self.c_decompose_point(t, point_name, x_name, y_name, c)
        t.to_top(point_name)
        split_fn = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(c.coord_bytes)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        }
        t.raw_block([point_name], "", split_fn)
        t.nm.push("_dp_xb")
        t.nm.push("_dp_yb")

        # Convert y_bytes (on top) to num
        rev_fn = c.reverse_bytes_fn
        convert_y = ->(e) {
          rev_fn.call(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_yb"], y_name, convert_y)

        # Convert x_bytes to num
        t.to_top("_dp_xb")
        convert_x = ->(e) {
          rev_fn.call(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        }
        t.raw_block(["_dp_xb"], x_name, convert_x)

        t.swap
      end

      def self.c_compose_point(t, x_name, y_name, result_name, c)
        num_bin_size = c.coord_bytes + 1
        rev_fn = c.reverse_bytes_fn

        t.to_top(x_name)
        convert_x = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(num_bin_size)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(make_stack_op(op: "push", value: big_int_push(c.coord_bytes)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          rev_fn.call(e)
        }
        t.raw_block([x_name], "_cp_xb", convert_x)

        t.to_top(y_name)
        convert_y = ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(num_bin_size)))
          e.call(make_stack_op(op: "opcode", code: "OP_NUM2BIN"))
          e.call(make_stack_op(op: "push", value: big_int_push(c.coord_bytes)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
          e.call(make_stack_op(op: "drop"))
          rev_fn.call(e)
        }
        t.raw_block([y_name], "_cp_yb", convert_y)

        t.to_top("_cp_xb")
        t.to_top("_cp_yb")
        t.raw_block(["_cp_xb", "_cp_yb"], result_name, ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_CAT")) })
      end

      # =================================================================
      # Affine point addition
      # =================================================================

      def self.c_affine_add(t, c)
        t.copy_to_top("qy", "_qy1")
        t.copy_to_top("py", "_py1")
        c_field_sub(t, "_qy1", "_py1", "_s_num", c)

        t.copy_to_top("qx", "_qx1")
        t.copy_to_top("px", "_px1")
        c_field_sub(t, "_qx1", "_px1", "_s_den", c)

        c_field_inv(t, "_s_den", "_s_den_inv", c)
        c_field_mul(t, "_s_num", "_s_den_inv", "_s", c)

        t.copy_to_top("_s", "_s_keep")
        c_field_sqr(t, "_s", "_s2", c)
        t.copy_to_top("px", "_px2")
        c_field_sub(t, "_s2", "_px2", "_rx1", c)
        t.copy_to_top("qx", "_qx2")
        c_field_sub(t, "_rx1", "_qx2", "rx", c)

        t.copy_to_top("px", "_px3")
        t.copy_to_top("rx", "_rx2")
        c_field_sub(t, "_px3", "_rx2", "_px_rx", c)
        c_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx", c)
        t.copy_to_top("py", "_py2")
        c_field_sub(t, "_s_px_rx", "_py2", "ry", c)

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
      # Jacobian point doubling with a=-3 optimization
      # =================================================================

      def self.c_jacobian_double(t, c)
        # Z^2
        t.copy_to_top("jz", "_jz_sq_tmp")
        c_field_sqr(t, "_jz_sq_tmp", "_Z2", c)

        # X - Z^2 and X + Z^2
        t.copy_to_top("jx", "_jx_c1")
        t.copy_to_top("_Z2", "_Z2_c1")
        c_field_sub(t, "_jx_c1", "_Z2_c1", "_X_minus_Z2", c)
        t.copy_to_top("jx", "_jx_c2")
        c_field_add(t, "_jx_c2", "_Z2", "_X_plus_Z2", c)

        # A = 3*(X-Z^2)*(X+Z^2)
        c_field_mul(t, "_X_minus_Z2", "_X_plus_Z2", "_prod", c)
        t.push_int("_three", 3)
        c_field_mul(t, "_prod", "_three", "_A", c)

        # B = 4*X*Y^2
        t.copy_to_top("jy", "_jy_sq_tmp")
        c_field_sqr(t, "_jy_sq_tmp", "_Y2", c)
        t.copy_to_top("_Y2", "_Y2_c1")
        t.copy_to_top("jx", "_jx_c3")
        c_field_mul(t, "_jx_c3", "_Y2", "_xY2", c)
        t.push_int("_four", 4)
        c_field_mul(t, "_xY2", "_four", "_B", c)

        # C = 8*Y^4
        c_field_sqr(t, "_Y2_c1", "_Y4", c)
        t.push_int("_eight", 8)
        c_field_mul(t, "_Y4", "_eight", "_C", c)

        # X3 = A^2 - 2*B
        t.copy_to_top("_A", "_A_save")
        t.copy_to_top("_B", "_B_save")
        c_field_sqr(t, "_A", "_A2", c)
        t.copy_to_top("_B", "_B_c1")
        c_field_mul_const(t, "_B_c1", 2, "_2B", c)
        c_field_sub(t, "_A2", "_2B", "_X3", c)

        # Y3 = A*(B - X3) - C
        t.copy_to_top("_X3", "_X3_c")
        c_field_sub(t, "_B_save", "_X3_c", "_B_minus_X3", c)
        c_field_mul(t, "_A_save", "_B_minus_X3", "_A_tmp", c)
        c_field_sub(t, "_A_tmp", "_C", "_Y3", c)

        # Z3 = 2*Y*Z
        t.copy_to_top("jy", "_jy_c")
        t.copy_to_top("jz", "_jz_c")
        c_field_mul(t, "_jy_c", "_jz_c", "_yz", c)
        c_field_mul_const(t, "_yz", 2, "_Z3", c)

        # Clean up and rename
        t.to_top("_B")
        t.drop
        t.to_top("jz")
        t.drop
        t.to_top("jx")
        t.drop
        t.to_top("jy")
        t.drop
        t.to_top("_X3")
        t.rename("jx")
        t.to_top("_Y3")
        t.rename("jy")
        t.to_top("_Z3")
        t.rename("jz")
      end

      # =================================================================
      # Jacobian to affine conversion
      # =================================================================

      def self.c_jacobian_to_affine(t, rx_name, ry_name, c)
        c_field_inv(t, "jz", "_zinv", c)
        t.copy_to_top("_zinv", "_zinv_keep")
        c_field_sqr(t, "_zinv", "_zinv2", c)
        t.copy_to_top("_zinv2", "_zinv2_keep")
        c_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3", c)
        c_field_mul(t, "jx", "_zinv2_keep", rx_name, c)
        c_field_mul(t, "jy", "_zinv3", ry_name, c)
      end

      # =================================================================
      # Jacobian mixed addition (P_jacobian + Q_affine)
      # =================================================================

      def self.c_build_jacobian_add_affine_inline(e, t, c)
        it = EC::ECTracker.new(t.nm.dup, e)

        it.copy_to_top("jz", "_jz_for_z1cu")
        it.copy_to_top("jz", "_jz_for_z3")
        it.copy_to_top("jy", "_jy_for_y3")
        it.copy_to_top("jx", "_jx_for_u1h2")

        c_field_sqr(it, "jz", "_Z1sq", c)

        it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
        c_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", c)

        it.copy_to_top("ax", "_ax_c")
        c_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2", c)

        it.copy_to_top("ay", "_ay_c")
        c_field_mul(it, "_ay_c", "_Z1cu", "_S2", c)

        c_field_sub(it, "_U2", "jx", "_H", c)
        c_field_sub(it, "_S2", "jy", "_R", c)

        it.copy_to_top("_H", "_H_for_h3")
        it.copy_to_top("_H", "_H_for_z3")

        c_field_sqr(it, "_H", "_H2", c)

        it.copy_to_top("_H2", "_H2_for_u1h2")

        c_field_mul(it, "_H_for_h3", "_H2", "_H3", c)
        c_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", c)

        it.copy_to_top("_R", "_R_for_y3")
        it.copy_to_top("_U1H2", "_U1H2_for_y3")
        it.copy_to_top("_H3", "_H3_for_y3")

        c_field_sqr(it, "_R", "_R2", c)
        c_field_sub(it, "_R2", "_H3", "_x3_tmp", c)
        c_field_mul_const(it, "_U1H2", 2, "_2U1H2", c)
        c_field_sub(it, "_x3_tmp", "_2U1H2", "_X3", c)

        it.copy_to_top("_X3", "_X3_c")
        c_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", c)
        c_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp", c)
        c_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", c)
        c_field_sub(it, "_r_tmp", "_jy_h3", "_Y3", c)

        c_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3", c)

        it.to_top("_X3")
        it.rename("jx")
        it.to_top("_Y3")
        it.rename("jy")
        it.to_top("_Z3")
        it.rename("jz")
      end

      # =================================================================
      # Scalar multiplication (generic for both P-256 and P-384)
      # =================================================================

      def self.c_emit_mul(emit, c, g)
        t = EC::ECTracker.new(["_pt", "_k"], emit)
        c_decompose_point(t, "_pt", "ax", "ay", c)

        # k' = k + 3n
        t.to_top("_k")
        t.push_big_int("_n", g.n)
        t.raw_block(["_k", "_n"], "_kn", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_big_int("_n2", g.n)
        t.raw_block(["_kn", "_n2"], "_kn2", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.push_big_int("_n3", g.n)
        t.raw_block(["_kn2", "_n3"], "_kn3", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_ADD")) })
        t.rename("_k")

        # Determine iteration count: highest bit of 4n-1
        four_n_minus1 = 4 * g.n - 1
        top_bit = bit_len(four_n_minus1)
        start_bit = top_bit - 2 # highest bit is always 1 (init), start from next

        # Init accumulator = P
        t.copy_to_top("ax", "jx")
        t.copy_to_top("ay", "jy")
        t.push_int("jz", 1)

        start_bit.downto(0) do |bit|
          c_jacobian_double(t, c)

          t.copy_to_top("_k", "_k_copy")
          if bit == 1
            t.raw_block(["_k_copy"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_2DIV")) })
          elsif bit > 1
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_RSHIFTNUM")) })
          else
            t.rename("_shifted")
          end
          t.push_int("_two", 2)
          t.raw_block(["_shifted", "_two"], "_bit", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_MOD")) })

          t.to_top("_bit")
          t.nm.pop # _bit consumed by IF

          add_ops = []
          add_emit = ->(op) { add_ops.push(op) }
          c_build_jacobian_add_affine_inline(add_emit, t, c)
          emit.call(make_stack_op(op: "if", then: add_ops, else_ops: []))
        end

        c_jacobian_to_affine(t, "_rx", "_ry", c)

        t.to_top("ax")
        t.drop
        t.to_top("ay")
        t.drop
        t.to_top("_k")
        t.drop

        c_compose_point(t, "_rx", "_ry", "_result", c)
      end

      # =================================================================
      # Square-and-multiply modular exponentiation (for sqrt)
      # =================================================================

      def self.c_field_pow(t, base_name, exp, result_name, c)
        bits = bit_len(exp)

        t.copy_to_top(base_name, "_pow_r")

        (bits - 2).downto(0) do |i|
          c_field_sqr(t, "_pow_r", "_pow_sq", c)
          t.rename("_pow_r")
          if exp[i] == 1
            t.copy_to_top(base_name, "_pow_b")
            c_field_mul(t, "_pow_r", "_pow_b", "_pow_m", c)
            t.rename("_pow_r")
          end
        end

        t.to_top(base_name)
        t.drop
        t.to_top("_pow_r")
        t.rename(result_name)
      end

      # =================================================================
      # Pubkey decompression (prefix byte + x → (x, y))
      # =================================================================

      def self.c_decompress_pub_key(t, pk_name, qx_name, qy_name, c, curve_b, sqrt_exp)
        t.to_top(pk_name)

        # Split: [prefix_byte, x_bytes]
        t.raw_block([pk_name], "", ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(1)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        })
        t.nm.push("_dk_prefix")
        t.nm.push("_dk_xbytes")

        # Convert prefix to parity: 0x02 → 0, 0x03 → 1
        t.to_top("_dk_prefix")
        t.raw_block(["_dk_prefix"], "_dk_parity", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
          e.call(make_stack_op(op: "push", value: big_int_push(2)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        })

        # Stash parity on altstack
        t.to_top("_dk_parity")
        t.to_alt

        # Convert x_bytes to number
        rev_fn = c.reverse_bytes_fn
        t.to_top("_dk_xbytes")
        t.raw_block(["_dk_xbytes"], "_dk_x", ->(e) {
          rev_fn.call(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        })

        # Save x for later
        t.copy_to_top("_dk_x", "_dk_x_save")

        # Compute y^2 = x^3 - 3x + b mod p
        t.copy_to_top("_dk_x", "_dk_x_c1")
        c_field_sqr(t, "_dk_x", "_dk_x2", c)
        c_field_mul(t, "_dk_x2", "_dk_x_c1", "_dk_x3", c)
        t.copy_to_top("_dk_x_save", "_dk_x_for_3")
        c_field_mul_const(t, "_dk_x_for_3", 3, "_dk_3x", c)
        c_field_sub(t, "_dk_x3", "_dk_3x", "_dk_x3m3x", c)
        t.push_big_int("_dk_b", curve_b)
        c_field_add(t, "_dk_x3m3x", "_dk_b", "_dk_y2", c)

        # y = (y^2)^sqrtExp mod p
        c_field_pow(t, "_dk_y2", sqrt_exp, "_dk_y_cand", c)

        # Check if candidate y has the right parity
        t.copy_to_top("_dk_y_cand", "_dk_y_check")
        t.raw_block(["_dk_y_check"], "_dk_y_par", ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(2)))
          e.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        })

        # Retrieve parity from altstack
        t.from_alt("_dk_parity")

        # Compare
        t.to_top("_dk_y_par")
        t.to_top("_dk_parity")
        t.raw_block(["_dk_y_par", "_dk_parity"], "_dk_match", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_EQUAL"))
        })

        # Compute p - y_cand
        t.copy_to_top("_dk_y_cand", "_dk_y_for_neg")
        c_push_field_p(t, "_dk_pfn", c)
        t.to_top("_dk_y_for_neg")
        t.raw_block(["_dk_pfn", "_dk_y_for_neg"], "_dk_neg_y", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        })

        # Use OP_IF to select: if match, use y_cand; else use neg_y
        t.to_top("_dk_match")
        t.nm.pop # condition consumed by IF

        then_ops = [make_stack_op(op: "drop")]
        else_ops = [make_stack_op(op: "nip")]
        t.e.call(make_stack_op(op: "if", then: then_ops, else_ops: else_ops))

        # Remove one item from tracker and rename the surviving item
        neg_idx = t.nm.rindex("_dk_neg_y")
        t.nm.delete_at(neg_idx) if neg_idx

        yc_idx = t.nm.rindex("_dk_y_cand")
        t.nm[yc_idx] = qy_name if yc_idx

        xs_idx = t.nm.rindex("_dk_x_save")
        t.nm[xs_idx] = qx_name if xs_idx
      end

      # =================================================================
      # ECDSA verification
      # =================================================================

      def self.c_emit_verify_ecdsa(emit, c, g, curve_b, sqrt_exp, gx, gy)
        t = EC::ECTracker.new(["_msg", "_sig", "_pk"], emit)

        # Step 1: e = SHA-256(msg) as integer
        t.to_top("_msg")
        t.raw_block(["_msg"], "_e", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_SHA256"))
          emit_reverse32(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        })

        # Step 2: Parse sig into (r, s)
        t.to_top("_sig")
        t.raw_block(["_sig"], "", ->(e) {
          e.call(make_stack_op(op: "push", value: big_int_push(c.coord_bytes)))
          e.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        })
        t.nm.push("_r_bytes")
        t.nm.push("_s_bytes")

        rev_fn = c.reverse_bytes_fn

        # Convert r_bytes to integer
        t.to_top("_r_bytes")
        t.raw_block(["_r_bytes"], "_r", ->(e) {
          rev_fn.call(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        })

        # Convert s_bytes to integer
        t.to_top("_s_bytes")
        t.raw_block(["_s_bytes"], "_s", ->(e) {
          rev_fn.call(e)
          e.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x00".b)))
          e.call(make_stack_op(op: "opcode", code: "OP_CAT"))
          e.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        })

        # Step 3: Decompress pubkey
        c_decompress_pub_key(t, "_pk", "_qx", "_qy", c, curve_b, sqrt_exp)

        # Step 4: w = s^{-1} mod n
        c_group_inv(t, "_s", "_w", g)

        # Step 5: u1 = e * w mod n
        t.copy_to_top("_w", "_w_c1")
        c_group_mul(t, "_e", "_w_c1", "_u1", g)

        # Step 6: u2 = r * w mod n
        t.copy_to_top("_r", "_r_save")
        c_group_mul(t, "_r", "_w", "_u2", g)

        # Step 7: R = u1*G + u2*Q
        point_bytes = c.coord_bytes * 2
        g_point = bigint_to_n_bytes(gx, c.coord_bytes) + bigint_to_n_bytes(gy, c.coord_bytes)
        t.push_bytes("_G", g_point)
        t.to_top("_u1")

        # Stash items on altstack
        t.to_top("_r_save")
        t.to_alt
        t.to_top("_u2")
        t.to_alt
        t.to_top("_qy")
        t.to_alt
        t.to_top("_qx")
        t.to_alt

        # Remove _G and _u1 from tracker before c_emit_mul
        t.nm.pop # _u1
        t.nm.pop # _G

        c_emit_mul(emit, c, g)

        # After mul, one result point is on the stack
        t.nm.push("_R1_point")

        # Pop qx/qy/u2 from altstack (LIFO order)
        t.from_alt("_qx")
        t.from_alt("_qy")
        t.from_alt("_u2")

        # Stash R1 point
        t.to_top("_R1_point")
        t.to_alt

        # Compose Q point
        c_compose_point(t, "_qx", "_qy", "_Q_point", c)

        t.to_top("_u2")

        # Remove from tracker, emit mul, push result
        t.nm.pop # _u2
        t.nm.pop # _Q_point
        c_emit_mul(emit, c, g)
        t.nm.push("_R2_point")

        # Restore R1 point
        t.from_alt("_R1_point")

        # Swap so R2 is on top
        t.swap

        # Decompose both, add
        c_decompose_point(t, "_R1_point", "_rpx", "_rpy", c)
        c_decompose_point(t, "_R2_point", "_rqx", "_rqy", c)

        # Rename to what c_affine_add expects
        rpx_idx = t.nm.rindex("_rpx"); t.nm[rpx_idx] = "px" if rpx_idx
        rpy_idx = t.nm.rindex("_rpy"); t.nm[rpy_idx] = "py" if rpy_idx
        rqx_idx = t.nm.rindex("_rqx"); t.nm[rqx_idx] = "qx" if rqx_idx
        rqy_idx = t.nm.rindex("_rqy"); t.nm[rqy_idx] = "qy" if rqy_idx

        c_affine_add(t, c)

        # Step 8: x_R mod n == r
        t.to_top("ry")
        t.drop

        c_group_mod(t, "rx", "_rx_mod_n", g)

        # Restore r
        t.from_alt("_r_save")

        # Compare
        t.to_top("_rx_mod_n")
        t.to_top("_r_save")
        t.raw_block(["_rx_mod_n", "_r_save"], "_result", ->(e) {
          e.call(make_stack_op(op: "opcode", code: "OP_EQUAL"))
        })
      end

      # =================================================================
      # P-256 public API
      # =================================================================

      def self.emit_p256_add(emit)
        t = EC::ECTracker.new(["_pa", "_pb"], emit)
        c_decompose_point(t, "_pa", "px", "py", P256_CURVE)
        c_decompose_point(t, "_pb", "qx", "qy", P256_CURVE)
        c_affine_add(t, P256_CURVE)
        c_compose_point(t, "rx", "ry", "_result", P256_CURVE)
      end

      def self.emit_p256_mul(emit)
        c_emit_mul(emit, P256_CURVE, P256_GROUP)
      end

      def self.emit_p256_mul_gen(emit)
        g_point = bigint_to_n_bytes(P256_GX, 32) + bigint_to_n_bytes(P256_GY, 32)
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: g_point)))
        emit.call(make_stack_op(op: "swap"))
        emit_p256_mul(emit)
      end

      def self.emit_p256_negate(emit)
        t = EC::ECTracker.new(["_pt"], emit)
        c_decompose_point(t, "_pt", "_nx", "_ny", P256_CURVE)
        c_push_field_p(t, "_fp", P256_CURVE)
        c_field_sub(t, "_fp", "_ny", "_neg_y", P256_CURVE)
        c_compose_point(t, "_nx", "_neg_y", "_result", P256_CURVE)
      end

      def self.emit_p256_on_curve(emit)
        t = EC::ECTracker.new(["_pt"], emit)
        c_decompose_point(t, "_pt", "_x", "_y", P256_CURVE)

        c_field_sqr(t, "_y", "_y2", P256_CURVE)

        t.copy_to_top("_x", "_x_copy")
        t.copy_to_top("_x", "_x_copy2")
        c_field_sqr(t, "_x", "_x2", P256_CURVE)
        c_field_mul(t, "_x2", "_x_copy", "_x3", P256_CURVE)
        c_field_mul_const(t, "_x_copy2", 3, "_3x", P256_CURVE)
        c_field_sub(t, "_x3", "_3x", "_x3m3x", P256_CURVE)
        t.push_big_int("_b", P256_B)
        c_field_add(t, "_x3m3x", "_b", "_rhs", P256_CURVE)

        t.to_top("_y2")
        t.to_top("_rhs")
        t.raw_block(["_y2", "_rhs"], "_result", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) })
      end

      def self.emit_p256_encode_compressed(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(32)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
        emit.call(make_stack_op(op: "push", value: big_int_push(1)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        emit.call(make_stack_op(op: "push", value: big_int_push(2)))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop"))
        emit.call(make_stack_op(
          op: "if",
          then: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x03".b))],
          else_ops: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x02".b))]
        ))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      def self.emit_verify_ecdsa_p256(emit)
        c_emit_verify_ecdsa(emit, P256_CURVE, P256_GROUP, P256_B, P256_SQRT_EXP, P256_GX, P256_GY)
      end

      # =================================================================
      # P-384 public API
      # =================================================================

      def self.emit_p384_add(emit)
        t = EC::ECTracker.new(["_pa", "_pb"], emit)
        c_decompose_point(t, "_pa", "px", "py", P384_CURVE)
        c_decompose_point(t, "_pb", "qx", "qy", P384_CURVE)
        c_affine_add(t, P384_CURVE)
        c_compose_point(t, "rx", "ry", "_result", P384_CURVE)
      end

      def self.emit_p384_mul(emit)
        c_emit_mul(emit, P384_CURVE, P384_GROUP)
      end

      def self.emit_p384_mul_gen(emit)
        g_point = bigint_to_n_bytes(P384_GX, 48) + bigint_to_n_bytes(P384_GY, 48)
        emit.call(make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: g_point)))
        emit.call(make_stack_op(op: "swap"))
        emit_p384_mul(emit)
      end

      def self.emit_p384_negate(emit)
        t = EC::ECTracker.new(["_pt"], emit)
        c_decompose_point(t, "_pt", "_nx", "_ny", P384_CURVE)
        c_push_field_p(t, "_fp", P384_CURVE)
        c_field_sub(t, "_fp", "_ny", "_neg_y", P384_CURVE)
        c_compose_point(t, "_nx", "_neg_y", "_result", P384_CURVE)
      end

      def self.emit_p384_on_curve(emit)
        t = EC::ECTracker.new(["_pt"], emit)
        c_decompose_point(t, "_pt", "_x", "_y", P384_CURVE)

        c_field_sqr(t, "_y", "_y2", P384_CURVE)

        t.copy_to_top("_x", "_x_copy")
        t.copy_to_top("_x", "_x_copy2")
        c_field_sqr(t, "_x", "_x2", P384_CURVE)
        c_field_mul(t, "_x2", "_x_copy", "_x3", P384_CURVE)
        c_field_mul_const(t, "_x_copy2", 3, "_3x", P384_CURVE)
        c_field_sub(t, "_x3", "_3x", "_x3m3x", P384_CURVE)
        t.push_big_int("_b", P384_B)
        c_field_add(t, "_x3m3x", "_b", "_rhs", P384_CURVE)

        t.to_top("_y2")
        t.to_top("_rhs")
        t.raw_block(["_y2", "_rhs"], "_result", ->(e) { e.call(make_stack_op(op: "opcode", code: "OP_EQUAL")) })
      end

      def self.emit_p384_encode_compressed(emit)
        emit.call(make_stack_op(op: "push", value: big_int_push(48)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SIZE"))
        emit.call(make_stack_op(op: "push", value: big_int_push(1)))
        emit.call(make_stack_op(op: "opcode", code: "OP_SUB"))
        emit.call(make_stack_op(op: "opcode", code: "OP_SPLIT"))
        emit.call(make_stack_op(op: "opcode", code: "OP_BIN2NUM"))
        emit.call(make_stack_op(op: "push", value: big_int_push(2)))
        emit.call(make_stack_op(op: "opcode", code: "OP_MOD"))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "drop"))
        emit.call(make_stack_op(
          op: "if",
          then: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x03".b))],
          else_ops: [make_stack_op(op: "push", value: make_push_value(kind: "bytes", bytes_val: "\x02".b))]
        ))
        emit.call(make_stack_op(op: "swap"))
        emit.call(make_stack_op(op: "opcode", code: "OP_CAT"))
      end

      def self.emit_verify_ecdsa_p384(emit)
        c_emit_verify_ecdsa(emit, P384_CURVE, P384_GROUP, P384_B, P384_SQRT_EXP, P384_GX, P384_GY)
      end

      # =================================================================
      # Dispatch table (called from stack.rb)
      # =================================================================

      NIST_EC_BUILTIN_NAMES = %w[
        p256Add p256Mul p256MulGen p256Negate p256OnCurve p256EncodeCompressed
        p384Add p384Mul p384MulGen p384Negate p384OnCurve p384EncodeCompressed
      ].to_set.freeze

      VERIFY_ECDSA_NAMES = %w[verifyECDSA_P256 verifyECDSA_P384].to_set.freeze

      def self.nist_ec_builtin?(name)
        NIST_EC_BUILTIN_NAMES.include?(name)
      end

      def self.verify_ecdsa_builtin?(name)
        VERIFY_ECDSA_NAMES.include?(name)
      end

      NIST_EC_DISPATCH = {
        "p256Add"              => method(:emit_p256_add),
        "p256Mul"              => method(:emit_p256_mul),
        "p256MulGen"           => method(:emit_p256_mul_gen),
        "p256Negate"           => method(:emit_p256_negate),
        "p256OnCurve"          => method(:emit_p256_on_curve),
        "p256EncodeCompressed" => method(:emit_p256_encode_compressed),
        "p384Add"              => method(:emit_p384_add),
        "p384Mul"              => method(:emit_p384_mul),
        "p384MulGen"           => method(:emit_p384_mul_gen),
        "p384Negate"           => method(:emit_p384_negate),
        "p384OnCurve"          => method(:emit_p384_on_curve),
        "p384EncodeCompressed" => method(:emit_p384_encode_compressed),
      }.freeze

      def self.dispatch_nist_ec_builtin(func_name, emit)
        fn = NIST_EC_DISPATCH[func_name]
        raise "unknown NIST EC builtin: #{func_name}" if fn.nil?
        fn.call(emit)
      end

      def self.dispatch_verify_ecdsa(func_name, emit)
        if func_name == "verifyECDSA_P256"
          emit_verify_ecdsa_p256(emit)
        else
          emit_verify_ecdsa_p384(emit)
        end
      end
    end
  end
end
