"""P-256 / P-384 codegen — NIST elliptic curve operations for Bitcoin Script.

Follows the same pattern as ec.py (secp256k1). Uses ECTracker for named
stack state tracking, but with different field primes, curve orders,
and generator points.

Point representation:
  P-256: 64 bytes (x[32] || y[32], big-endian unsigned)
  P-384: 96 bytes (x[48] || y[48], big-endian unsigned)

Key difference from secp256k1: curve parameter a = -3 (not 0), which gives
an optimised Jacobian doubling formula.

Direct port of ``compilers/go/codegen/p256_p384.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue

# Re-use ECTracker and the lazy-import helpers from ec.py
from runar_compiler.codegen.ec import (
    ECTracker,
    _make_stack_op,
    _make_push_value,
    _big_int_push,
)

# ===========================================================================
# P-256 constants (secp256r1 / NIST P-256)
# ===========================================================================

P256_P    = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
P256_B    = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
P256_N    = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
P256_GX   = int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
P256_GY   = int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
# sqrt exp = (p + 1) / 4
P256_SQRT_EXP = (P256_P + 1) >> 2
P256_P_MINUS_2 = P256_P - 2
P256_N_MINUS_2 = P256_N - 2

# ===========================================================================
# P-384 constants (secp384r1 / NIST P-384)
# ===========================================================================

P384_P    = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16)
P384_B    = int("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16)
P384_N    = int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16)
P384_GX   = int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16)
P384_GY   = int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)
P384_SQRT_EXP = (P384_P + 1) >> 2
P384_P_MINUS_2 = P384_P - 2
P384_N_MINUS_2 = P384_N - 2


# ===========================================================================
# Utility helpers
# ===========================================================================

def _bigint_to_n_bytes(n: int, size: int) -> bytes:
    """Convert an int to a *size*-byte big-endian byte string."""
    return n.to_bytes(size, byteorder="big")


def _bigint_bit_len(n: int) -> int:
    return n.bit_length()


# ===========================================================================
# Byte reversal for 48 bytes (P-384)
# ===========================================================================

def _emit_reverse48(e: Callable) -> None:
    """Emit inline byte reversal for a 48-byte value on TOS."""
    e(_make_stack_op(op="opcode", code="OP_0"))
    e(_make_stack_op(op="swap"))
    for _ in range(48):
        e(_make_stack_op(op="push", value=_big_int_push(1)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="rot"))
        e(_make_stack_op(op="rot"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="swap"))
    e(_make_stack_op(op="drop"))


# Re-use 32-byte reversal from ec.py
def _emit_reverse32(e: Callable) -> None:
    from runar_compiler.codegen.ec import _ec_emit_reverse32
    _ec_emit_reverse32(e)


# ===========================================================================
# Generic field arithmetic parameterised by prime
# ===========================================================================

def _c_push_field_p(t: ECTracker, name: str, field_p: int) -> None:
    t.push_big_int(name, field_p)


def _c_field_mod(t: ECTracker, a_name: str, result_name: str, field_p: int) -> None:
    t.to_top(a_name)
    _c_push_field_p(t, "_fmod_p", field_p)

    def _fn(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_2DUP"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))
        e(_make_stack_op(op="rot"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="over"))
        e(_make_stack_op(op="opcode", code="OP_ADD"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block([a_name, "_fmod_p"], result_name, _fn)


def _c_field_add(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int) -> None:
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fadd_sum", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    _c_field_mod(t, "_fadd_sum", result_name, field_p)


def _c_field_sub(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int) -> None:
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fsub_diff", lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))
    _c_field_mod(t, "_fsub_diff", result_name, field_p)


def _c_field_mul(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int) -> None:
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fmul_prod", lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    _c_field_mod(t, "_fmul_prod", result_name, field_p)


def _c_field_mul_const(t: ECTracker, a_name: str, cv: int, result_name: str, field_p: int) -> None:
    t.to_top(a_name)

    def _fmc_body(e: Callable) -> None:
        if cv == 2:
            e(_make_stack_op(op="opcode", code="OP_2MUL"))
        else:
            e(_make_stack_op(op="push", value=_big_int_push(cv)))
            e(_make_stack_op(op="opcode", code="OP_MUL"))

    t.raw_block([a_name], "_fmc_prod", _fmc_body)
    _c_field_mod(t, "_fmc_prod", result_name, field_p)


def _c_field_sqr(t: ECTracker, a_name: str, result_name: str, field_p: int) -> None:
    t.copy_to_top(a_name, "_fsqr_copy")
    _c_field_mul(t, a_name, "_fsqr_copy", result_name, field_p)


def _c_field_inv(t: ECTracker, a_name: str, result_name: str, field_p: int, p_minus_2: int) -> None:
    """Compute a^(p-2) mod p via generic square-and-multiply."""
    exp = p_minus_2
    bits = _bigint_bit_len(exp)

    t.copy_to_top(a_name, "_inv_r")

    for i in range(bits - 2, -1, -1):
        _c_field_sqr(t, "_inv_r", "_inv_r2", field_p)
        t.rename("_inv_r")
        if (exp >> i) & 1 == 1:
            t.copy_to_top(a_name, "_inv_a")
            _c_field_mul(t, "_inv_r", "_inv_a", "_inv_m", field_p)
            t.rename("_inv_r")

    t.to_top(a_name)
    t.drop()
    t.to_top("_inv_r")
    t.rename(result_name)


# ===========================================================================
# Group-order arithmetic (for ECDSA: mod n operations)
# ===========================================================================

def _c_push_group_n(t: ECTracker, name: str, curve_n: int) -> None:
    t.push_big_int(name, curve_n)


def _c_group_mod(t: ECTracker, a_name: str, result_name: str, curve_n: int) -> None:
    t.to_top(a_name)
    _c_push_group_n(t, "_gmod_n", curve_n)

    def _fn(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_2DUP"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))
        e(_make_stack_op(op="rot"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="over"))
        e(_make_stack_op(op="opcode", code="OP_ADD"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block([a_name, "_gmod_n"], result_name, _fn)


def _c_group_mul(t: ECTracker, a_name: str, b_name: str, result_name: str, curve_n: int) -> None:
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_gmul_prod", lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    _c_group_mod(t, "_gmul_prod", result_name, curve_n)


def _c_group_inv(t: ECTracker, a_name: str, result_name: str, curve_n: int, n_minus_2: int) -> None:
    """Compute a^(n-2) mod n via square-and-multiply."""
    exp = n_minus_2
    bits = _bigint_bit_len(exp)

    t.copy_to_top(a_name, "_ginv_r")

    for i in range(bits - 2, -1, -1):
        t.copy_to_top("_ginv_r", "_ginv_sq_copy")
        _c_group_mul(t, "_ginv_r", "_ginv_sq_copy", "_ginv_sq", curve_n)
        t.rename("_ginv_r")
        if (exp >> i) & 1 == 1:
            t.copy_to_top(a_name, "_ginv_a")
            _c_group_mul(t, "_ginv_r", "_ginv_a", "_ginv_m", curve_n)
            t.rename("_ginv_r")

    t.to_top(a_name)
    t.drop()
    t.to_top("_ginv_r")
    t.rename(result_name)


# ===========================================================================
# Point decompose / compose (parameterised by coordinate byte size)
# ===========================================================================

def _c_decompose_point(
    t: ECTracker,
    point_name: str,
    x_name: str,
    y_name: str,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
) -> None:
    t.to_top(point_name)

    def _split(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(coord_bytes)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))

    t.raw_block([point_name], "", _split)
    t.nm.append("_dp_xb")
    t.nm.append("_dp_yb")

    def _convert_y(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_dp_yb"], y_name, _convert_y)

    t.to_top("_dp_xb")

    def _convert_x(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_dp_xb"], x_name, _convert_x)

    # Swap to standard order [x_name, y_name]
    t.swap()


def _c_compose_point(
    t: ECTracker,
    x_name: str,
    y_name: str,
    result_name: str,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
) -> None:
    num_bin_size = coord_bytes + 1

    t.to_top(x_name)

    def _convert_x(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(num_bin_size)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="push", value=_big_int_push(coord_bytes)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        reverse_bytes_fn(e)

    t.raw_block([x_name], "_cp_xb", _convert_x)

    t.to_top(y_name)

    def _convert_y(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(num_bin_size)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="push", value=_big_int_push(coord_bytes)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        reverse_bytes_fn(e)

    t.raw_block([y_name], "_cp_yb", _convert_y)

    t.to_top("_cp_xb")
    t.to_top("_cp_yb")
    t.raw_block(["_cp_xb", "_cp_yb"], result_name, lambda e: e(_make_stack_op(op="opcode", code="OP_CAT")))


# ===========================================================================
# Affine point addition (parameterised by curve)
# ===========================================================================

def _c_affine_add(t: ECTracker, field_p: int, p_minus_2: int) -> None:
    """Perform affine point addition.

    Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
    """
    t.copy_to_top("qy", "_qy1")
    t.copy_to_top("py", "_py1")
    _c_field_sub(t, "_qy1", "_py1", "_s_num", field_p)

    t.copy_to_top("qx", "_qx1")
    t.copy_to_top("px", "_px1")
    _c_field_sub(t, "_qx1", "_px1", "_s_den", field_p)

    _c_field_inv(t, "_s_den", "_s_den_inv", field_p, p_minus_2)
    _c_field_mul(t, "_s_num", "_s_den_inv", "_s", field_p)

    t.copy_to_top("_s", "_s_keep")
    _c_field_sqr(t, "_s", "_s2", field_p)
    t.copy_to_top("px", "_px2")
    _c_field_sub(t, "_s2", "_px2", "_rx1", field_p)
    t.copy_to_top("qx", "_qx2")
    _c_field_sub(t, "_rx1", "_qx2", "rx", field_p)

    t.copy_to_top("px", "_px3")
    t.copy_to_top("rx", "_rx2")
    _c_field_sub(t, "_px3", "_rx2", "_px_rx", field_p)
    _c_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx", field_p)
    t.copy_to_top("py", "_py2")
    _c_field_sub(t, "_s_px_rx", "_py2", "ry", field_p)

    t.to_top("px")
    t.drop()
    t.to_top("py")
    t.drop()
    t.to_top("qx")
    t.drop()
    t.to_top("qy")
    t.drop()


# ===========================================================================
# Jacobian point doubling with a=-3 optimisation (P-256, P-384)
# ===========================================================================

def _c_jacobian_double(t: ECTracker, field_p: int, p_minus_2: int) -> None:
    """Jacobian doubling for a=-3 curves.

    Uses optimisation: A = 3*(X - Z^2)*(X + Z^2) instead of 3*X^2 + a*Z^4.
    Expects jx, jy, jz. Replaces with updated values.
    """
    # Z^2
    t.copy_to_top("jz", "_jz_sq_tmp")
    _c_field_sqr(t, "_jz_sq_tmp", "_Z2", field_p)

    # X - Z^2 and X + Z^2
    t.copy_to_top("jx", "_jx_c1")
    t.copy_to_top("_Z2", "_Z2_c1")
    _c_field_sub(t, "_jx_c1", "_Z2_c1", "_X_minus_Z2", field_p)
    t.copy_to_top("jx", "_jx_c2")
    _c_field_add(t, "_jx_c2", "_Z2", "_X_plus_Z2", field_p)

    # A = 3*(X-Z^2)*(X+Z^2)
    _c_field_mul(t, "_X_minus_Z2", "_X_plus_Z2", "_prod", field_p)
    t.push_int("_three", 3)
    _c_field_mul(t, "_prod", "_three", "_A", field_p)

    # B = 4*X*Y^2
    t.copy_to_top("jy", "_jy_sq_tmp")
    _c_field_sqr(t, "_jy_sq_tmp", "_Y2", field_p)
    t.copy_to_top("_Y2", "_Y2_c1")
    t.copy_to_top("jx", "_jx_c3")
    _c_field_mul(t, "_jx_c3", "_Y2", "_xY2", field_p)
    t.push_int("_four", 4)
    _c_field_mul(t, "_xY2", "_four", "_B", field_p)

    # C = 8*Y^4
    _c_field_sqr(t, "_Y2_c1", "_Y4", field_p)
    t.push_int("_eight", 8)
    _c_field_mul(t, "_Y4", "_eight", "_C", field_p)

    # X3 = A^2 - 2*B
    t.copy_to_top("_A", "_A_save")
    t.copy_to_top("_B", "_B_save")
    _c_field_sqr(t, "_A", "_A2", field_p)
    t.copy_to_top("_B", "_B_c1")
    _c_field_mul_const(t, "_B_c1", 2, "_2B", field_p)
    _c_field_sub(t, "_A2", "_2B", "_X3", field_p)

    # Y3 = A*(B - X3) - C
    t.copy_to_top("_X3", "_X3_c")
    _c_field_sub(t, "_B_save", "_X3_c", "_B_minus_X3", field_p)
    _c_field_mul(t, "_A_save", "_B_minus_X3", "_A_tmp", field_p)
    _c_field_sub(t, "_A_tmp", "_C", "_Y3", field_p)

    # Z3 = 2*Y*Z
    t.copy_to_top("jy", "_jy_c")
    t.copy_to_top("jz", "_jz_c")
    _c_field_mul(t, "_jy_c", "_jz_c", "_yz", field_p)
    _c_field_mul_const(t, "_yz", 2, "_Z3", field_p)

    # Clean up and rename
    t.to_top("_B")
    t.drop()
    t.to_top("jz")
    t.drop()
    t.to_top("jx")
    t.drop()
    t.to_top("jy")
    t.drop()
    t.to_top("_X3")
    t.rename("jx")
    t.to_top("_Y3")
    t.rename("jy")
    t.to_top("_Z3")
    t.rename("jz")


# ===========================================================================
# Jacobian to affine conversion
# ===========================================================================

def _c_jacobian_to_affine(
    t: ECTracker, rx_name: str, ry_name: str, field_p: int, p_minus_2: int
) -> None:
    """Convert jx, jy, jz → rx_name, ry_name (affine)."""
    _c_field_inv(t, "jz", "_zinv", field_p, p_minus_2)
    t.copy_to_top("_zinv", "_zinv_keep")
    _c_field_sqr(t, "_zinv", "_zinv2", field_p)
    t.copy_to_top("_zinv2", "_zinv2_keep")
    _c_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3", field_p)
    _c_field_mul(t, "jx", "_zinv2_keep", rx_name, field_p)
    _c_field_mul(t, "jy", "_zinv3", ry_name, field_p)


# ===========================================================================
# Jacobian mixed addition inline (for use inside OP_IF)
# ===========================================================================

def _c_build_jacobian_add_affine_inline(
    e: Callable,
    t: ECTracker,
    field_p: int,
    p_minus_2: int,
) -> None:
    """Build Jacobian mixed-add ops for use inside OP_IF."""
    it = ECTracker(list(t.nm), e)

    it.copy_to_top("jz", "_jz_for_z1cu")
    it.copy_to_top("jz", "_jz_for_z3")
    it.copy_to_top("jy", "_jy_for_y3")
    it.copy_to_top("jx", "_jx_for_u1h2")

    _c_field_sqr(it, "jz", "_Z1sq", field_p)

    it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
    _c_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu", field_p)

    it.copy_to_top("ax", "_ax_c")
    _c_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2", field_p)

    it.copy_to_top("ay", "_ay_c")
    _c_field_mul(it, "_ay_c", "_Z1cu", "_S2", field_p)

    _c_field_sub(it, "_U2", "jx", "_H", field_p)
    _c_field_sub(it, "_S2", "jy", "_R", field_p)

    it.copy_to_top("_H", "_H_for_h3")
    it.copy_to_top("_H", "_H_for_z3")

    _c_field_sqr(it, "_H", "_H2", field_p)

    it.copy_to_top("_H2", "_H2_for_u1h2")

    _c_field_mul(it, "_H_for_h3", "_H2", "_H3", field_p)
    _c_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2", field_p)

    it.copy_to_top("_R", "_R_for_y3")
    it.copy_to_top("_U1H2", "_U1H2_for_y3")
    it.copy_to_top("_H3", "_H3_for_y3")

    _c_field_sqr(it, "_R", "_R2", field_p)
    _c_field_sub(it, "_R2", "_H3", "_x3_tmp", field_p)
    _c_field_mul_const(it, "_U1H2", 2, "_2U1H2", field_p)
    _c_field_sub(it, "_x3_tmp", "_2U1H2", "_X3", field_p)

    it.copy_to_top("_X3", "_X3_c")
    _c_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x", field_p)
    _c_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp", field_p)
    _c_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3", field_p)
    _c_field_sub(it, "_r_tmp", "_jy_h3", "_Y3", field_p)

    _c_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3", field_p)

    it.to_top("_X3")
    it.rename("jx")
    it.to_top("_Y3")
    it.rename("jy")
    it.to_top("_Z3")
    it.rename("jz")


# ===========================================================================
# Scalar multiplication (generic for both P-256 and P-384)
# ===========================================================================

def _c_emit_mul(
    emit: Callable,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
    field_p: int,
    p_minus_2: int,
    curve_n: int,
    n_minus_2: int,
) -> None:
    """Generic scalar multiplication for NIST curves."""
    t = ECTracker(["_pt", "_k"], emit)
    _c_decompose_point(t, "_pt", "ax", "ay", coord_bytes, reverse_bytes_fn)

    # k' = k + 3n
    t.to_top("_k")
    t.push_big_int("_n", curve_n)
    t.raw_block(["_k", "_n"], "_kn", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_n2", curve_n)
    t.raw_block(["_kn", "_n2"], "_kn2", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_n3", curve_n)
    t.raw_block(["_kn2", "_n3"], "_kn3", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.rename("_k")

    # top bit: 4n-1 bit length
    four_n_minus_1 = 4 * curve_n - 1
    top_bit = four_n_minus_1.bit_length()
    start_bit = top_bit - 2  # highest bit always 1 (init), start from next

    # Init accumulator = P
    t.copy_to_top("ax", "jx")
    t.copy_to_top("ay", "jy")
    t.push_int("jz", 1)

    for bit in range(start_bit, -1, -1):
        _c_jacobian_double(t, field_p, p_minus_2)

        t.copy_to_top("_k", "_k_copy")
        if bit == 1:
            t.raw_block(["_k_copy"], "_shifted", lambda e: e(_make_stack_op(op="opcode", code="OP_2DIV")))
        elif bit > 1:
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted", lambda e: e(_make_stack_op(op="opcode", code="OP_RSHIFTNUM")))
        else:
            t.rename("_shifted")
        t.push_int("_two", 2)
        t.raw_block(["_shifted", "_two"], "_bit", lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))

        t.to_top("_bit")
        t.nm.pop()  # _bit consumed by IF

        add_ops: list = []

        def _add_emit(op: object, _t: ECTracker = t, _fp: int = field_p, _pm2: int = p_minus_2) -> None:
            add_ops.append(op)

        _c_build_jacobian_add_affine_inline(_add_emit, t, field_p, p_minus_2)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

    _c_jacobian_to_affine(t, "_rx", "_ry", field_p, p_minus_2)

    t.to_top("ax")
    t.drop()
    t.to_top("ay")
    t.drop()
    t.to_top("_k")
    t.drop()

    _c_compose_point(t, "_rx", "_ry", "_result", coord_bytes, reverse_bytes_fn)


# ===========================================================================
# Square-and-multiply modular exponentiation (for sqrt)
# ===========================================================================

def _c_field_pow(
    t: ECTracker, base_name: str, exp: int, result_name: str, field_p: int, p_minus_2: int
) -> None:
    bits = _bigint_bit_len(exp)
    t.copy_to_top(base_name, "_pow_r")

    for i in range(bits - 2, -1, -1):
        _c_field_sqr(t, "_pow_r", "_pow_sq", field_p)
        t.rename("_pow_r")
        if (exp >> i) & 1 == 1:
            t.copy_to_top(base_name, "_pow_b")
            _c_field_mul(t, "_pow_r", "_pow_b", "_pow_m", field_p)
            t.rename("_pow_r")

    t.to_top(base_name)
    t.drop()
    t.to_top("_pow_r")
    t.rename(result_name)


# ===========================================================================
# Pubkey decompression (prefix byte + x → (x, y))
# ===========================================================================

def _c_decompress_pub_key(
    t: ECTracker,
    pk_name: str,
    qx_name: str,
    qy_name: str,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
    field_p: int,
    p_minus_2: int,
    curve_b: int,
    sqrt_exp: int,
) -> None:
    t.to_top(pk_name)

    def _split_prefix(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(1)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))

    t.raw_block([pk_name], "", _split_prefix)
    t.nm.append("_dk_prefix")
    t.nm.append("_dk_xbytes")

    t.to_top("_dk_prefix")

    def _prefix_to_parity(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
        e(_make_stack_op(op="push", value=_big_int_push(2)))
        e(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block(["_dk_prefix"], "_dk_parity", _prefix_to_parity)

    t.to_top("_dk_parity")
    t.to_alt()

    t.to_top("_dk_xbytes")

    def _xbytes_to_num(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_dk_xbytes"], "_dk_x", _xbytes_to_num)

    t.copy_to_top("_dk_x", "_dk_x_save")

    # Compute y^2 = x^3 - 3x + b mod p
    t.copy_to_top("_dk_x", "_dk_x_c1")
    _c_field_sqr(t, "_dk_x", "_dk_x2", field_p)
    _c_field_mul(t, "_dk_x2", "_dk_x_c1", "_dk_x3", field_p)
    t.copy_to_top("_dk_x_save", "_dk_x_for_3")
    _c_field_mul_const(t, "_dk_x_for_3", 3, "_dk_3x", field_p)
    _c_field_sub(t, "_dk_x3", "_dk_3x", "_dk_x3m3x", field_p)
    t.push_big_int("_dk_b", curve_b)
    _c_field_add(t, "_dk_x3m3x", "_dk_b", "_dk_y2", field_p)

    # y = (y^2)^sqrtExp mod p
    _c_field_pow(t, "_dk_y2", sqrt_exp, "_dk_y_cand", field_p, p_minus_2)

    # Check parity
    t.copy_to_top("_dk_y_cand", "_dk_y_check")

    def _check_parity(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(2)))
        e(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block(["_dk_y_check"], "_dk_y_par", _check_parity)

    t.from_alt("_dk_parity")

    t.to_top("_dk_y_par")
    t.to_top("_dk_parity")
    t.raw_block(["_dk_y_par", "_dk_parity"], "_dk_match", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))

    # Compute p - y_cand
    t.copy_to_top("_dk_y_cand", "_dk_y_for_neg")
    _c_push_field_p(t, "_dk_pfn", field_p)
    t.to_top("_dk_y_for_neg")
    t.raw_block(["_dk_pfn", "_dk_y_for_neg"], "_dk_neg_y", lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))

    t.to_top("_dk_match")
    t.nm.pop()  # condition consumed by IF

    then_ops = [_make_stack_op(op="drop")]   # remove neg_y, keep y_cand
    else_ops = [_make_stack_op(op="nip")]    # remove y_cand, keep neg_y
    t.e(_make_stack_op(op="if", then=then_ops, else_=else_ops))

    # Remove neg_y from tracker
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_dk_neg_y":
            del t.nm[i]
            break

    # Rename y_cand to qy_name
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_dk_y_cand":
            t.nm[i] = qy_name
            break

    # Rename x_save to qx_name
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_dk_x_save":
            t.nm[i] = qx_name
            break


# ===========================================================================
# ECDSA verification (generic)
# ===========================================================================

def _c_emit_verify_ecdsa(
    emit: Callable,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
    field_p: int,
    p_minus_2: int,
    curve_n: int,
    n_minus_2: int,
    curve_b: int,
    sqrt_exp: int,
    gx: int,
    gy: int,
) -> None:
    t = ECTracker(["_msg", "_sig", "_pk"], emit)

    # Step 1: e = SHA-256(msg) as integer
    t.to_top("_msg")

    def _hash_msg(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_SHA256"))
        _emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_msg"], "_e", _hash_msg)

    # Step 2: Parse sig into (r, s)
    t.to_top("_sig")

    def _split_sig(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(coord_bytes)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))

    t.raw_block(["_sig"], "", _split_sig)
    t.nm.append("_r_bytes")
    t.nm.append("_s_bytes")

    t.to_top("_r_bytes")

    def _r_to_num(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_r_bytes"], "_r", _r_to_num)

    t.to_top("_s_bytes")

    def _s_to_num(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_s_bytes"], "_s", _s_to_num)

    # Step 3: Decompress pubkey
    _c_decompress_pub_key(
        t, "_pk", "_qx", "_qy",
        coord_bytes, reverse_bytes_fn,
        field_p, p_minus_2, curve_b, sqrt_exp,
    )

    # Step 4: w = s^{-1} mod n
    _c_group_inv(t, "_s", "_w", curve_n, n_minus_2)

    # Step 5: u1 = e * w mod n
    t.copy_to_top("_w", "_w_c1")
    _c_group_mul(t, "_e", "_w_c1", "_u1", curve_n)

    # Step 6: u2 = r * w mod n
    t.copy_to_top("_r", "_r_save")
    _c_group_mul(t, "_r", "_w", "_u2", curve_n)

    # Step 7: R = u1*G + u2*Q
    point_bytes = coord_bytes * 2
    g_point_data = _bigint_to_n_bytes(gx, coord_bytes) + _bigint_to_n_bytes(gy, coord_bytes)
    t.push_bytes("_G", g_point_data)
    t.to_top("_u1")

    # Stash items on altstack
    t.to_top("_r_save")
    t.to_alt()
    t.to_top("_u2")
    t.to_alt()
    t.to_top("_qy")
    t.to_alt()
    t.to_top("_qx")
    t.to_alt()

    # Remove _G and _u1 from tracker before cEmitMul
    t.nm.pop()  # _u1
    t.nm.pop()  # _G

    _c_emit_mul(emit, coord_bytes, reverse_bytes_fn, field_p, p_minus_2, curve_n, n_minus_2)

    t.nm.append("_R1_point")

    t.from_alt("_qx")
    t.from_alt("_qy")
    t.from_alt("_u2")

    t.to_top("_R1_point")
    t.to_alt()

    _c_compose_point(t, "_qx", "_qy", "_Q_point", coord_bytes, reverse_bytes_fn)

    t.to_top("_u2")

    t.nm.pop()  # _u2
    t.nm.pop()  # _Q_point

    _c_emit_mul(emit, coord_bytes, reverse_bytes_fn, field_p, p_minus_2, curve_n, n_minus_2)
    t.nm.append("_R2_point")

    t.from_alt("_R1_point")

    t.swap()

    _c_decompose_point(t, "_R1_point", "_rpx", "_rpy", coord_bytes, reverse_bytes_fn)
    _c_decompose_point(t, "_R2_point", "_rqx", "_rqy", coord_bytes, reverse_bytes_fn)

    # Rename to what _c_affine_add expects
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_rpx":
            t.nm[i] = "px"
            break
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_rpy":
            t.nm[i] = "py"
            break
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_rqx":
            t.nm[i] = "qx"
            break
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_rqy":
            t.nm[i] = "qy"
            break

    _c_affine_add(t, field_p, p_minus_2)

    # Step 8: x_R mod n == r
    t.to_top("ry")
    t.drop()

    _c_group_mod(t, "rx", "_rx_mod_n", curve_n)

    t.from_alt("_r_save")

    t.to_top("_rx_mod_n")
    t.to_top("_r_save")
    t.raw_block(
        ["_rx_mod_n", "_r_save"],
        "_result",
        lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")),
    )


# ===========================================================================
# P-256 public API
# ===========================================================================

def emit_p256_add(emit: Callable) -> None:
    """Add two P-256 points. Stack in: [pa, pb], out: [result]."""
    t = ECTracker(["_pa", "_pb"], emit)
    _c_decompose_point(t, "_pa", "px", "py", 32, _emit_reverse32)
    _c_decompose_point(t, "_pb", "qx", "qy", 32, _emit_reverse32)
    _c_affine_add(t, P256_P, P256_P_MINUS_2)
    _c_compose_point(t, "rx", "ry", "_result", 32, _emit_reverse32)


def emit_p256_mul(emit: Callable) -> None:
    """P-256 scalar multiplication. Stack in: [point, scalar], out: [result]."""
    _c_emit_mul(emit, 32, _emit_reverse32, P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2)


def emit_p256_mul_gen(emit: Callable) -> None:
    """P-256 generator multiplication. Stack in: [scalar], out: [result]."""
    g_point = _bigint_to_n_bytes(P256_GX, 32) + _bigint_to_n_bytes(P256_GY, 32)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_p256_mul(emit)


def emit_p256_negate(emit: Callable) -> None:
    """Negate a P-256 point. Stack in: [point], out: [negated_point]."""
    t = ECTracker(["_pt"], emit)
    _c_decompose_point(t, "_pt", "_nx", "_ny", 32, _emit_reverse32)
    _c_push_field_p(t, "_fp", P256_P)
    _c_field_sub(t, "_fp", "_ny", "_neg_y", P256_P)
    _c_compose_point(t, "_nx", "_neg_y", "_result", 32, _emit_reverse32)


def emit_p256_on_curve(emit: Callable) -> None:
    """Check if a P-256 point is on the curve (y^2 = x^3 - 3x + b mod p)."""
    t = ECTracker(["_pt"], emit)
    _c_decompose_point(t, "_pt", "_x", "_y", 32, _emit_reverse32)

    _c_field_sqr(t, "_y", "_y2", P256_P)

    t.copy_to_top("_x", "_x_copy")
    t.copy_to_top("_x", "_x_copy2")
    _c_field_sqr(t, "_x", "_x2", P256_P)
    _c_field_mul(t, "_x2", "_x_copy", "_x3", P256_P)
    _c_field_mul_const(t, "_x_copy2", 3, "_3x", P256_P)
    _c_field_sub(t, "_x3", "_3x", "_x3m3x", P256_P)
    t.push_big_int("_b", P256_B)
    _c_field_add(t, "_x3m3x", "_b", "_rhs", P256_P)

    t.to_top("_y2")
    t.to_top("_rhs")
    t.raw_block(["_y2", "_rhs"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))


def emit_p256_encode_compressed(emit: Callable) -> None:
    """Encode a P-256 point as 33-byte compressed pubkey."""
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_SIZE"))
    emit(_make_stack_op(op="push", value=_big_int_push(1)))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    emit(_make_stack_op(op="push", value=_big_int_push(2)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(
        op="if",
        then=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x03"))],
        else_=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x02"))],
    ))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


def emit_verify_ecdsa_p256(emit: Callable) -> None:
    """Verify an ECDSA signature on P-256.

    Stack in: [msg, sig (64 bytes r||s), pk (33 bytes compressed)]
    Stack out: [boolean]
    """
    _c_emit_verify_ecdsa(
        emit,
        coord_bytes=32,
        reverse_bytes_fn=_emit_reverse32,
        field_p=P256_P,
        p_minus_2=P256_P_MINUS_2,
        curve_n=P256_N,
        n_minus_2=P256_N_MINUS_2,
        curve_b=P256_B,
        sqrt_exp=P256_SQRT_EXP,
        gx=P256_GX,
        gy=P256_GY,
    )


# ===========================================================================
# P-384 public API
# ===========================================================================

def emit_p384_add(emit: Callable) -> None:
    """Add two P-384 points. Stack in: [pa, pb], out: [result]."""
    t = ECTracker(["_pa", "_pb"], emit)
    _c_decompose_point(t, "_pa", "px", "py", 48, _emit_reverse48)
    _c_decompose_point(t, "_pb", "qx", "qy", 48, _emit_reverse48)
    _c_affine_add(t, P384_P, P384_P_MINUS_2)
    _c_compose_point(t, "rx", "ry", "_result", 48, _emit_reverse48)


def emit_p384_mul(emit: Callable) -> None:
    """P-384 scalar multiplication. Stack in: [point, scalar], out: [result]."""
    _c_emit_mul(emit, 48, _emit_reverse48, P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2)


def emit_p384_mul_gen(emit: Callable) -> None:
    """P-384 generator multiplication. Stack in: [scalar], out: [result]."""
    g_point = _bigint_to_n_bytes(P384_GX, 48) + _bigint_to_n_bytes(P384_GY, 48)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_p384_mul(emit)


def emit_p384_negate(emit: Callable) -> None:
    """Negate a P-384 point. Stack in: [point], out: [negated_point]."""
    t = ECTracker(["_pt"], emit)
    _c_decompose_point(t, "_pt", "_nx", "_ny", 48, _emit_reverse48)
    _c_push_field_p(t, "_fp", P384_P)
    _c_field_sub(t, "_fp", "_ny", "_neg_y", P384_P)
    _c_compose_point(t, "_nx", "_neg_y", "_result", 48, _emit_reverse48)


def emit_p384_on_curve(emit: Callable) -> None:
    """Check if a P-384 point is on the curve (y^2 = x^3 - 3x + b mod p)."""
    t = ECTracker(["_pt"], emit)
    _c_decompose_point(t, "_pt", "_x", "_y", 48, _emit_reverse48)

    _c_field_sqr(t, "_y", "_y2", P384_P)

    t.copy_to_top("_x", "_x_copy")
    t.copy_to_top("_x", "_x_copy2")
    _c_field_sqr(t, "_x", "_x2", P384_P)
    _c_field_mul(t, "_x2", "_x_copy", "_x3", P384_P)
    _c_field_mul_const(t, "_x_copy2", 3, "_3x", P384_P)
    _c_field_sub(t, "_x3", "_3x", "_x3m3x", P384_P)
    t.push_big_int("_b", P384_B)
    _c_field_add(t, "_x3m3x", "_b", "_rhs", P384_P)

    t.to_top("_y2")
    t.to_top("_rhs")
    t.raw_block(["_y2", "_rhs"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))


def emit_p384_encode_compressed(emit: Callable) -> None:
    """Encode a P-384 point as 49-byte compressed pubkey."""
    emit(_make_stack_op(op="push", value=_big_int_push(48)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_SIZE"))
    emit(_make_stack_op(op="push", value=_big_int_push(1)))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    emit(_make_stack_op(op="push", value=_big_int_push(2)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(
        op="if",
        then=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x03"))],
        else_=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x02"))],
    ))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


def emit_verify_ecdsa_p384(emit: Callable) -> None:
    """Verify an ECDSA signature on P-384.

    Stack in: [msg, sig (96 bytes r||s), pk (49 bytes compressed)]
    Stack out: [boolean]
    """
    _c_emit_verify_ecdsa(
        emit,
        coord_bytes=48,
        reverse_bytes_fn=_emit_reverse48,
        field_p=P384_P,
        p_minus_2=P384_P_MINUS_2,
        curve_n=P384_N,
        n_minus_2=P384_N_MINUS_2,
        curve_b=P384_B,
        sqrt_exp=P384_SQRT_EXP,
        gx=P384_GX,
        gy=P384_GY,
    )
