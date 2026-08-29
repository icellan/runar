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
    Dom,
    EcCodegenOptions,
    ECTracker,
    POOL_FIELD_P,
    POOL_GROUP_N,
    is_non_negative,
    _comb_emit_select,
    _make_stack_op,
    _make_push_value,
    _big_int_push,
)
from runar_compiler.codegen.comb import (
    P256_COMB_CURVE,
    P384_COMB_CURVE,
    CombCurve,
    comb_geometry,
    comb_safe_rounds,
    comb_table,
)
from runar_compiler.codegen.cost_model import estimate_script_bytes

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
    t.push_const(POOL_FIELD_P, field_p, name)


def _c_field_mod_short(t: ECTracker, a_name: str, result_name: str, field_p: int) -> None:
    """``a mod p`` with no sign fix-up: 1 opcode instead of 7. Sound only when
    the dividend is provably >= 0 -- the caller proves that, this does not check.
    """
    t.to_top(a_name)
    _c_push_field_p(t, "_fmods_p", field_p)
    t.raw_block([a_name, "_fmods_p"], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))
    t.set_domain(result_name, Dom.REDUCED)


def _c_cheap_sub_pays(t: ECTracker, field_p: int) -> bool:
    """Does the cheap ``a - b + p`` subtraction pay? Only when p is pooled."""
    cost = t.const_cost(POOL_FIELD_P, field_p)
    return 2 * cost + 2 < cost + 8


def _c_field_mod(t: ECTracker, a_name: str, result_name: str, field_p: int) -> None:
    if t.sinking and is_non_negative(t.domain_of(a_name)):
        _c_field_mod_short(t, a_name, result_name, field_p)
        return
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
    t.set_domain(result_name, Dom.REDUCED)


def _c_field_add(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int) -> None:
    # Read the operand facts before raw_block consumes their slots.
    sum_non_neg = is_non_negative(t.domain_of(a_name)) and is_non_negative(t.domain_of(b_name))
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fadd_sum", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    if sum_non_neg:
        t.set_domain("_fadd_sum", Dom.NON_NEGATIVE)
    _c_field_mod(t, "_fadd_sum", result_name, field_p)


def _c_field_sub(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int) -> None:
    t.to_top(a_name)
    t.to_top(b_name)
    # Needs a >= 0 AND b in [0, p): then a - b > -p and one shifted reduction is
    # exact. `b >= 0` alone is not enough -- a coordinate decoded from 32
    # unsigned bytes may exceed p by up to 2^32 + 977.
    cheap = (t.sinking
             and is_non_negative(t.domain_of(a_name))
             and t.domain_of(b_name) == Dom.REDUCED
             and _c_cheap_sub_pays(t, field_p))

    t.raw_block([a_name, b_name], "_fsub_diff", lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))

    if cheap:
        _c_push_field_p(t, "_fsub_p", field_p)
        t.raw_block(["_fsub_diff", "_fsub_p"], "_fsub_shift",
                    lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
        t.set_domain("_fsub_shift", Dom.NON_NEGATIVE)
        _c_field_mod_short(t, "_fsub_shift", result_name, field_p)
        return
    _c_field_mod(t, "_fsub_diff", result_name, field_p)


def _c_field_mul(t: ECTracker, a_name: str, b_name: str, result_name: str, field_p: int,
                 product_non_negative: bool = False) -> None:
    # *product_non_negative* lets `_c_field_sqr` assert the sign independently of
    # the operand: a*a >= 0 for any a whatsoever.
    non_neg = product_non_negative or (
        is_non_negative(t.domain_of(a_name)) and is_non_negative(t.domain_of(b_name)))
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fmul_prod", lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    if non_neg:
        t.set_domain("_fmul_prod", Dom.NON_NEGATIVE)
    _c_field_mod(t, "_fmul_prod", result_name, field_p)


def _c_field_mul_const(t: ECTracker, a_name: str, cv: int, result_name: str, field_p: int) -> None:
    # Every call site passes a small positive cv, so the product keeps a's sign.
    non_neg = cv > 0 and is_non_negative(t.domain_of(a_name))
    t.to_top(a_name)

    def _fmc_body(e: Callable) -> None:
        if cv == 2:
            e(_make_stack_op(op="opcode", code="OP_2MUL"))
        else:
            e(_make_stack_op(op="push", value=_big_int_push(cv)))
            e(_make_stack_op(op="opcode", code="OP_MUL"))

    t.raw_block([a_name], "_fmc_prod", _fmc_body)
    if non_neg:
        t.set_domain("_fmc_prod", Dom.NON_NEGATIVE)
    _c_field_mod(t, "_fmc_prod", result_name, field_p)


def _c_field_sqr(t: ECTracker, a_name: str, result_name: str, field_p: int) -> None:
    t.copy_to_top(a_name, "_fsqr_copy")
    _c_field_mul(t, a_name, "_fsqr_copy", result_name, field_p, product_non_negative=True)


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
    t.push_const(POOL_GROUP_N, curve_n, name)


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


def _c_emit_scalar_reduce(t: ECTracker, k_name: str, result_name: str, curve_n: int) -> None:
    """Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.

    OP_MOD takes the sign of the DIVIDEND, so ``k mod n`` alone lands in
    (-n, n); the ``+ n, mod n`` normalises the negative half. One push of n
    covers both reductions -- the same shape as ``emit_ec_mod_reduce``.

    Without it, ``_c_emit_mul``'s ladder is only correct while
    2^b <= k + 3n < 2^(b+1) for the fixed b it unrolls: a scalar >= ~n sets a
    bit above the loop's top, the loop never sees it, and the ladder returns a
    DIFFERENT multiple of P rather than failing. Scalars are contract input, so
    that is attacker-chosen. Reducing costs 1 push + 8 opcodes (42 / 58 bytes)
    against a ~460 KB / 1.6 MB script, and makes k >= n, k < 0 and k = 0 all
    well defined.
    """
    _c_push_group_n(t, "_n_red", curve_n)

    def _body(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_2DUP"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))
        e(_make_stack_op(op="rot"))
        e(_make_stack_op(op="drop"))
        e(_make_stack_op(op="over"))
        e(_make_stack_op(op="opcode", code="OP_ADD"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block([k_name, "_n_red"], result_name, _body)


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
    t.push_tracked("_dp_xb", Dom.UNKNOWN)
    t.push_tracked("_dp_yb", Dom.UNKNOWN)

    def _convert_y(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_dp_yb"], y_name, _convert_y)
    # A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    # UNSIGNED: >= 0, but it may be up to 2^(8*coord_bytes) - 1 and therefore
    # >= p. That gap is exactly what the subtraction precondition turns on.
    t.set_domain(y_name, Dom.NON_NEGATIVE)

    t.to_top("_dp_xb")

    def _convert_x(e: Callable) -> None:
        reverse_bytes_fn(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))

    t.raw_block(["_dp_xb"], x_name, _convert_x)
    t.set_domain(x_name, Dom.NON_NEGATIVE)

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

def _c_emit_canonicity_guard(t: ECTracker, x_name: str, y_name: str, field_p: int) -> None:
    """GAP-301: coordinate canonicity, leaving ``_canon`` on the tracker.

    ``_c_decompose_point`` BIN2NUMs each coordinate as an unsigned value that
    may be >= p; the curve equation reduces it mod p, so (x + p)||y would pass
    as a point it is not the canonical encoding of. Reject it: require x < p
    AND y < p (coordinates are unsigned, so the 0 <= bound holds by
    construction). The caller ANDs ``_canon`` into its result so the check
    still returns a boolean. This mirrors secp256k1's ``emit_ec_on_curve``,
    whose guard the a = -3 curves never received -- leaving ``pNNNOnCurve``
    accepting inputs ``ecOnCurve`` rejects even though both are documented as
    THE gate for untrusted points.
    """
    t.copy_to_top(x_name, "_x_lt")
    _c_push_field_p(t, "_p_for_x", field_p)
    t.raw_block(["_x_lt", "_p_for_x"], "_x_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.copy_to_top(y_name, "_y_lt")
    _c_push_field_p(t, "_p_for_y", field_p)
    t.raw_block(["_y_lt", "_p_for_y"], "_y_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.to_top("_x_canon")
    t.to_top("_y_canon")
    t.raw_block(["_x_canon", "_y_canon"], "_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))


def _c_affine_add(t: ECTracker, field_p: int, p_minus_2: int) -> None:
    """Perform affine point addition.

    Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.

    The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
    denominator is zero and the correct slope is the TANGENT, (3px^2 + a)/(2py)
    -- and a = -3 on both NIST curves, so the numerator is 3px^2 - 3. The
    secp256k1 fix (a = 0) was never ported here, so p256Add(P, P) and
    p384Add(P, P) produced a wrong point and every contract that doubled
    deployed an unspendable script.

    Both cases are ``s = num / den``, so only the NUMERATOR and DENOMINATOR are
    selected and the single expensive _c_field_inv still runs exactly once.
    rx and ry below are already correct for doubling.

      cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
      num    = cond ? 3*px^2 - 3 : (qy - py)
      den    = cond ? 2*py       : (qx - px)

    selected as ``b + cond*(a - b)``, which needs no branch and keeps the
    emitted op sequence identical on both paths.

    THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
    sends it down the tangent path and returns 2P -- an on-curve, entirely
    plausible, WRONG point, which is strictly worse than the pre-fix chord
    path: that one divided by zero (_c_field_inv is Fermat, inv(0) = 0) and
    produced an OFF-curve blob, so ``assert(pNNNOnCurve(pNNNAdd(a, b)))`` --
    the idiom examples/ts/p384-primitives writes verbatim -- rejected it.

    P + (-P) is the point at infinity, which affine x||y cannot represent. This
    codegen already has a representation for O: the ALL-ZERO blob, which is what
    ``pNNNMul(P, 0n)`` returns. So return that, by masking the result with
    ``notinf = NOT(px == qx AND NOT cond)``. O is not on the curve (0^2 != b),
    so the on-curve gate rejects it and the idiom works again; and it adds no
    failure channel to a pure value-producing expression, the same reason
    _c_emit_scalar_reduce reduces instead of rejecting.

    The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
    and notinf is 0 or 1, so the product is canonical either way.
    """
    t.copy_to_top("px", "_px_eq")
    t.copy_to_top("qx", "_qx_eq")
    t.raw_block(["_px_eq", "_qx_eq"], "_xeq",
                lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    t.copy_to_top("py", "_py_eq")
    t.copy_to_top("qy", "_qy_eq")
    t.raw_block(["_py_eq", "_qy_eq"], "_yeq",
                lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    t.copy_to_top("_xeq", "_xeq_c")
    t.to_top("_yeq")
    t.raw_block(["_xeq_c", "_yeq"], "_cond",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # notinf = NOT(xeq - cond): 1 exactly when px == qx and the points differ.
    t.to_top("_xeq")
    t.copy_to_top("_cond", "_cond_c")

    def _sub_not(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_SUB"))
        e(_make_stack_op(op="opcode", code="OP_NOT"))

    t.raw_block(["_xeq", "_cond_c"], "_notinf", _sub_not)

    # chord numerator / denominator
    t.copy_to_top("qy", "_qy1")
    t.copy_to_top("py", "_py1")
    _c_field_sub(t, "_qy1", "_py1", "_num_chord", field_p)
    t.copy_to_top("qx", "_qx1")
    t.copy_to_top("px", "_px1")
    _c_field_sub(t, "_qx1", "_px1", "_den_chord", field_p)

    # tangent numerator / denominator: 3*px^2 + a (a = -3) and 2*py
    t.copy_to_top("px", "_px_t")
    _c_field_sqr(t, "_px_t", "_px_sq", field_p)
    _c_field_mul_const(t, "_px_sq", 3, "_3px_sq", field_p)
    t.push_int("_a_neg", 3)
    _c_field_sub(t, "_3px_sq", "_a_neg", "_num_tan", field_p)
    t.copy_to_top("py", "_py_t")
    _c_field_mul_const(t, "_py_t", 2, "_den_tan", field_p)

    # num = num_chord + cond*(num_tan - num_chord)
    t.copy_to_top("_num_chord", "_num_chord_c")
    _c_field_sub(t, "_num_tan", "_num_chord_c", "_num_diff", field_p)
    t.copy_to_top("_cond", "_cond_n")
    _c_field_mul(t, "_num_diff", "_cond_n", "_num_sel", field_p)
    _c_field_add(t, "_num_chord", "_num_sel", "_s_num", field_p)

    # den = den_chord + cond*(den_tan - den_chord)
    t.copy_to_top("_den_chord", "_den_chord_c")
    _c_field_sub(t, "_den_tan", "_den_chord_c", "_den_diff", field_p)
    t.to_top("_cond")
    t.rename("_cond_d")
    _c_field_mul(t, "_den_diff", "_cond_d", "_den_sel", field_p)
    _c_field_add(t, "_den_chord", "_den_sel", "_s_den", field_p)

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

    # P == -Q -> force the all-zero point (see the header comment).
    t.to_top("rx")
    t.copy_to_top("_notinf", "_notinf_x")
    t.raw_block(["rx", "_notinf_x"], "rx",
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    t.to_top("ry")
    t.to_top("_notinf")
    t.raw_block(["ry", "_notinf"], "ry",
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))


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
    # The inner tracker inherits the stack state AND the lattice facts: the
    # operands' proved domains are what decide which reduction shape the body
    # emits, so dropping them here would silently fall back everywhere.
    _c_jacobian_add_affine_body(
        ECTracker(list(t.nm), e, t.options, list(t.dm)), False, field_p, p_minus_2)


def _c_jacobian_add_affine_body(
    it: ECTracker,
    keep_hr: bool,
    field_p: int,
    p_minus_2: int,
) -> None:
    """The mixed-add itself, emitting through a tracker the caller owns.

    ``keep_hr`` additionally leaves copies of H and R on the stack: both are
    zero exactly when the Jacobian accumulator is the same curve point as the
    affine operand, the one case these formulas cannot compute. See
    _c_build_jacobian_add_or_double_inline.
    """
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

    if keep_hr:
        it.copy_to_top("_H", "_H_keep")
        it.copy_to_top("_R", "_R_keep")

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


def _c_select_coord(
    t: ECTracker,
    add_name: str,
    dbl_name: str,
    cond_name: str,
    result_name: str,
    field_p: int,
) -> None:
    """Branchless select of one Jacobian coordinate: ``add + cond*(dbl - add)``.

    Consumes add_name, dbl_name and cond_name.
    """
    t.copy_to_top(add_name, "_sel_add_c")
    _c_field_sub(t, dbl_name, "_sel_add_c", "_sel_diff", field_p)
    _c_field_mul(t, "_sel_diff", cond_name, "_sel_scaled", field_p)
    _c_field_add(t, add_name, "_sel_scaled", result_name, field_p)


def _c_build_jacobian_add_or_double_inline(
    e: Callable,
    t: ECTracker,
    field_p: int,
    p_minus_2: int,
) -> None:
    """The ladder's LAST conditional step: mixed-add, but correct when the
    accumulator already equals the point being added.

    The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
    two operands are the same curve point H = 0, so Z3 = Z1*H = 0 -- the point
    at infinity -- and since _c_field_inv is Fermat (inv(0) = 0),
    _c_jacobian_to_affine turns that into the ALL-ZERO point instead of 2P.
    p256Mul(P, 2n) and p384Mul(P, 2n) returned 64 / 96 zero bytes.

    WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
    c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
    (c_i - 1)*P. P-256 and P-384 both have cofactor 1, so P has order n and the
    degenerate cases are exactly c_i == 2 (mod n) -- accumulator == P -- and
    c_i == 0 or 1 (mod n) -- accumulator == -P or O. c_i ranges over a
    CONTIGUOUS interval determined only by i, so this is decidable by interval
    arithmetic rather than by sampling, and over the whole domain k in [0, n-1]
    only two steps qualify, both at i = 0:

      k = 2  ->  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P. <- bug
      k = 0  ->  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
                 true result the point at infinity, which affine coordinates
                 cannot represent; it stays the all-zero point, as before.

    At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] -- the lower bound is 3n, not
    3n+1, because the reduce puts k = 0 in the domain.

    Handling H == 0 at every step would cost ~75% more script bytes -- on P-384
    that is another 600 KB; handling it here costs ~0.2%. The operand P is
    caller-supplied but cannot move the exception, because the condition depends
    only on c_i mod ord(P) and ord(P) = n for every point on these curves.
    Points that are NOT on the curve carry no such guarantee -- gate untrusted
    input on p256OnCurve / p384OnCurve first. _c_decompress_pub_key now enforces
    that itself for the one in-tree caller that takes a pubkey as input.

    THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
    because _c_emit_mul reduces k mod n before adding 3n. That reduce landed one
    commit AFTER this select (03f50d48 then f16790a9). 03f50d48 ON ITS OWN IS
    UNSOUND: a last-step-only select while the scalar is still unbounded leaves
    c_i free to hit 0, 1 or 2 (mod n) at other steps. The two commits must land
    together and must never be bisected, cherry-picked or reverted apart.

    The interval argument does 100% of the work; there is no defence in depth
    here. In particular c_i == 1 (mod n) -- a pre-add accumulator of O -- is
    UNREACHABLE, not handled: were it reachable the select would still take the
    ADD path, because O is carried as Z1 = 0, which makes U2 = 0 and
    H = -X1 != 0. Anything that changes the +3n offset, the iteration count or
    the reduce must redo the interval check, not assume this still holds.

    Stack layout: [..., ax, ay, _k, jx, jy, jz] -- same in and out.
    """
    it = ECTracker(list(t.nm), e, t.options, list(t.dm))

    # Keep the pre-add accumulator: it is what must be DOUBLED in the
    # exceptional case, and the add below consumes jx/jy/jz.
    it.copy_to_top("jx", "_sx")
    it.copy_to_top("jy", "_sy")
    it.copy_to_top("jz", "_sz")

    _c_jacobian_add_affine_body(it, True, field_p, p_minus_2)

    # cond = (H == 0) AND (R == 0). Requiring R == 0 too keeps the
    # accumulator == -P case (k = 0) on the add path, where Z3 = 0 correctly
    # signals the point at infinity.
    it.to_top("_H_keep")
    it.push_int("_zero_h", 0)
    it.raw_block(["_H_keep", "_zero_h"], "_h_is0",
                 lambda e2: e2(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    it.to_top("_R_keep")
    it.push_int("_zero_r", 0)
    it.raw_block(["_R_keep", "_zero_r"], "_r_is0",
                 lambda e2: e2(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    it.to_top("_h_is0")
    it.to_top("_r_is0")
    it.raw_block(["_h_is0", "_r_is0"], "_cond",
                 lambda e2: e2(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # Move the add result aside so _c_jacobian_double can work on jx/jy/jz
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
    _c_jacobian_double(it, field_p, p_minus_2)
    it.to_top("jx")
    it.rename("_dbl_x")
    it.to_top("jy")
    it.rename("_dbl_y")
    it.to_top("jz")
    it.rename("_dbl_z")

    it.copy_to_top("_cond", "_cond_x")
    _c_select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx", field_p)
    it.copy_to_top("_cond", "_cond_y")
    _c_select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy", field_p)
    it.to_top("_cond")
    it.rename("_cond_z")
    _c_select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz", field_p)


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
    opts: "EcCodegenOptions | None" = None,
) -> None:
    """Generic scalar multiplication for NIST curves."""
    t = ECTracker(["_pt", "_k"], emit, opts)
    t.pool_constant(POOL_FIELD_P, field_p)
    t.pool_constant(POOL_GROUP_N, curve_n)
    _c_decompose_point(t, "_pt", "ax", "ay", coord_bytes, reverse_bytes_fn)

    # k' = k + 3n
    #
    # The "k in [1, n-1]" precondition is one the caller cannot enforce -- the
    # scalar is usually an unlock argument -- so reduce it first.
    t.to_top("_k")
    _c_emit_scalar_reduce(t, "_k", "_kr", curve_n)
    t.push_big_int("_n", curve_n)
    t.raw_block(["_kr", "_n"], "_kn", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
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
        t.pop_tracked()  # _bit consumed by IF

        add_ops: list = []

        def _add_emit(op: object, _t: ECTracker = t, _fp: int = field_p, _pm2: int = p_minus_2) -> None:
            add_ops.append(op)

        # Only the final step can be handed two equal operands -- see
        # _c_build_jacobian_add_or_double_inline for why, and for what it
        # costs not to.
        if bit == 0:
            _c_build_jacobian_add_or_double_inline(_add_emit, t, field_p, p_minus_2)
        else:
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
    t.release_constant(POOL_GROUP_N)
    t.release_constant(POOL_FIELD_P)


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
    """Decompress a compressed pubkey: [prefix||x] -> (x_num, y_num, valid).

    For P-256/P-384 where a = -3:
      y^2 = x^3 - 3x + b mod p
      y = (y^2)^((p+1)/4) mod p
      Select y or p-y based on prefix parity.

    ``(y^2)^((p+1)/4)`` is a square root ONLY when y^2 is a quadratic residue;
    both primes are == 3 (mod 4), so for a non-residue it returns a square root
    of -y^2 instead and the recovered point is NOT on the curve. Nor is x
    checked against p: _c_decompose_point-style BIN2NUM accepts any
    width-fitting value and every field op silently reduces it, so a
    non-canonical x decompresses happily too.

    Both matter because the only consumer is _c_emit_verify_ecdsa, which feeds
    the result straight into _c_emit_mul. That ladder's exception analysis (see
    _c_build_jacobian_add_or_double_inline) is stated for points ON the curve,
    where cofactor 1 pins ord(P) = n; an off-curve point lands on the twist,
    whose order is composite, so the degenerate steps the interval argument
    rules out become reachable. The pubkey is a caller-supplied unlock argument.

    So this emits a third output, ``_dk_valid`` = (x < p) AND (y_cand^2 == y^2)
    AND (prefix in {0x02, 0x03}), which the caller ANDs into the verifier's
    boolean result. A flag, not an OP_VERIFY: ``verifyECDSA_*`` is a total
    boolean-valued builtin and turning attacker-chosen bytes into a script abort
    would be a liveness regression -- the same argument _c_emit_scalar_reduce
    makes for reducing rather than rejecting.
    """
    t.to_top(pk_name)

    def _split_prefix(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(1)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))

    t.raw_block([pk_name], "", _split_prefix)
    t.push_tracked("_dk_prefix", Dom.UNKNOWN)
    t.push_tracked("_dk_xbytes", Dom.UNKNOWN)

    # SEC1 sec 2.3.4 requires the prefix to be exactly 0x02 or 0x03. The parity
    # reduction below is ``BIN2NUM, 2 MOD``, which accepts far more than that:
    # 0x00 / 0x04 / 0x82 all alias to "even", and 0x83 is worse than an alias --
    # BIN2NUM(0x83) = -3 (sign-magnitude), -3 mod 2 = -1, which encodes as 0x81
    # and can never equal ``_dk_y_par`` in {<>, 0x01}, so the select silently
    # returns the OTHER square root. Test the byte itself.
    t.copy_to_top("_dk_prefix", "_dk_pfx_in")

    def _prefix_is_valid(e: Callable) -> None:
        e(_make_stack_op(op="dup"))
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x02")))
        e(_make_stack_op(op="opcode", code="OP_EQUAL"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x03")))
        e(_make_stack_op(op="opcode", code="OP_EQUAL"))
        e(_make_stack_op(op="opcode", code="OP_BOOLOR"))

    t.raw_block(["_dk_pfx_in"], "_dk_pfx_ok", _prefix_is_valid)

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

    # y = (y^2)^sqrtExp mod p. _c_field_pow CONSUMES its base, so keep a copy of
    # y^2 for the residue check at the end. It has to sit BELOW _dk_y_cand: the
    # parity select below is an OP_IF whose branches are a bare drop / nip, so
    # nothing may come between _dk_y_cand and the negated candidate.
    t.copy_to_top("_dk_y2", "_dk_y2_keep")
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
    t.pop_tracked()  # condition consumed by IF

    then_ops = [_make_stack_op(op="drop")]   # remove neg_y, keep y_cand
    else_ops = [_make_stack_op(op="nip")]    # remove y_cand, keep neg_y
    t.e(_make_stack_op(op="if", then=then_ops, else_=else_ops))

    # Remove neg_y from tracker
    for i in range(len(t.nm) - 1, -1, -1):
        if t.nm[i] == "_dk_neg_y":
            t.remove_slot_at(i)
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

    # valid = (qy^2 == y^2) AND (qx < p) AND (prefix in {0x02, 0x03}).
    # The selected qy is y_cand or p - y_cand, so squaring it tests the same
    # residue property either way. The first conjunct rejects an x whose RHS is
    # a quadratic non-residue -- the recovered point is then off the curve; the
    # second rejects a non-canonical encoding of an otherwise fine x; the third
    # rejects a prefix byte the parity reduction would otherwise alias or, for
    # 0x83, silently invert.
    t.copy_to_top(qy_name, "_dk_y_sq_in")
    _c_field_sqr(t, "_dk_y_sq_in", "_dk_y_sq", field_p)
    t.to_top("_dk_y_sq")
    t.to_top("_dk_y2_keep")
    t.raw_block(["_dk_y_sq", "_dk_y2_keep"], "_dk_res_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    t.copy_to_top(qx_name, "_dk_x_lt")
    _c_push_field_p(t, "_dk_p_lt", field_p)
    t.raw_block(["_dk_x_lt", "_dk_p_lt"], "_dk_x_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.to_top("_dk_res_ok")
    t.to_top("_dk_x_ok")
    t.raw_block(["_dk_res_ok", "_dk_x_ok"], "_dk_curve_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.to_top("_dk_pfx_ok")
    t.raw_block(["_dk_curve_ok", "_dk_pfx_ok"], "_dk_valid",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))


# ===========================================================================
# ECDSA verification (generic)
# ===========================================================================

def _c_emit_length_gate(t: ECTracker, name: str, want: int, flag_name: str) -> None:
    """Length gate for an untrusted byte argument: leaves ``[flag, clamped]``.

    ``flag`` is ``OP_SIZE(v) == want``; ``clamped`` is *v* forced to exactly
    *want* bytes by ``v || 00*want``, split at *want*, tail dropped -- truncating
    a long value and zero-extending a short one.

    The clamp exists so the gate can stay a FLAG. Everything downstream peels a
    fixed number of bytes (``OP_SPLIT coord_bytes``, then the 32/48 single-byte
    splits inside _emit_reverse32/_emit_reverse48); handed 32 <= len(sig) < 64
    the reversal runs out of bytes mid-loop and the SCRIPT ABORTS, which would
    make ``verifyECDSA_P256(...) || fallback`` unwritable and contradict this
    module's own totality rule (see _c_decompress_pub_key). Clamping first makes
    every path total; the caller ANDs *flag* into the result so a wrong-length
    argument can never verify whatever the clamped bytes computed.

    Branch-free on purpose: the tracker's static stack model, and the emitted op
    sequence, are the same for every input length -- the argument _c_affine_add
    makes for selecting operands instead of branching.
    """
    t.to_top(name)

    def _gate(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_SIZE"))
        e(_make_stack_op(op="push", value=_big_int_push(want)))
        e(_make_stack_op(op="opcode", code="OP_NUMEQUAL"))
        e(_make_stack_op(op="swap"))
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=bytes(want))))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="push", value=_big_int_push(want)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))

    t.raw_block([name], "", _gate)
    t.push_tracked(flag_name, Dom.UNKNOWN)
    t.push_tracked(name, Dom.UNKNOWN)


def _c_emit_sig_range_gate(t: ECTracker, curve_n: int) -> None:
    """SEC1 sec 4.1.4 step 1 / FIPS 186-5 sec 6.4.2: verify 1 <= r <= n-1 and
    1 <= s <= n-1. Consumes nothing, leaves ``_range_ok`` above ``_r`` and
    ``_s``.

    ==> THIS IS A UNIVERSAL FORGERY GUARD, NOT A HYGIENE CHECK. <==

    Nothing checked r or s at all, and _c_group_inv is Fermat (a^(n-2) mod n),
    so inv(0) = 0 instead of an error. With ``sig = 0x00...`` and the contract's
    own genuine, PUBLIC key:

      r = s = 0            (BIN2NUM of coord_bytes zero bytes -> empty vector)
      w = s^(n-2) = 0      Fermat, no failure channel
      u1 = u2 = 0          every _c_group_mul in the ladder is 0*0 mod n
      R1 = R2 = O          _c_emit_mul reduces 0, k' = 3n = 0 mod n, so Z3 = 0
                           and _c_jacobian_to_affine's Fermat inverse turns it
                           all-zero
      R1 + R2              _c_affine_add sees xeq = yeq = 1, takes the tangent
                           with den = 2*0 = 0, so s = 0 and rx = ry = 0
      (R.x mod n) == r     OP_EQUAL(<>, <>) = 1

    ...and ``_dk_valid`` is 1 because the pubkey is genuine. TRUE. No secret, no
    off-curve point, not bound to the message: an all-zero signature verified
    for ANY message under ANY public key. ``examples/ts/p256-wallet`` made
    exactly that call its second authentication factor.

    BOTH conjuncts are load-bearing and neither is redundant:
      - s = 0 (or s = n, which Fermat also inverts to 0) is what collapses both
        ladders to O;
      - r = 0 is what makes the final OP_EQUAL compare the resulting 0 against
        something that is also 0.
    ``r = 0, s = n`` is a second spelling of the same forgery that an ``s != 0``
    check alone would miss, which is why the bound is ``< n`` and not ``!= 0``.

    A flag rather than an OP_VERIFY, for the reason _c_decompress_pub_key gives.
    """
    t.copy_to_top("_r", "_r_nz_in")
    t.raw_block(["_r_nz_in"], "_r_nz",
                lambda e: e(_make_stack_op(op="opcode", code="OP_0NOTEQUAL")))
    t.copy_to_top("_r", "_r_lt_in")
    _c_push_group_n(t, "_n_for_r", curve_n)
    t.raw_block(["_r_lt_in", "_n_for_r"], "_r_lt",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.raw_block(["_r_nz", "_r_lt"], "_r_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    t.copy_to_top("_s", "_s_nz_in")
    t.raw_block(["_s_nz_in"], "_s_nz",
                lambda e: e(_make_stack_op(op="opcode", code="OP_0NOTEQUAL")))
    t.copy_to_top("_s", "_s_lt_in")
    _c_push_group_n(t, "_n_for_s", curve_n)
    t.raw_block(["_s_lt_in", "_n_for_s"], "_s_lt",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.raw_block(["_s_nz", "_s_lt"], "_s_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    t.raw_block(["_r_ok", "_s_ok"], "_range_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))


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
    comb_curve: "CombCurve | None" = None,
    opts: "EcCodegenOptions | None" = None,
) -> None:
    t = ECTracker(["_msg", "_sig", "_pk"], emit, opts)
    # The verifier does hundreds of reductions OUTSIDE the two ladders --
    # decompression's sqrt ladder, _c_group_inv, _c_affine_add, the final
    # _c_group_mod. Each ladder pools separately: _c_emit_mul runs on its own
    # tracker that deliberately cannot see this stack, so it cannot reach this
    # slot.
    t.pool_constant(POOL_FIELD_P, field_p)
    t.pool_constant(POOL_GROUP_N, curve_n)

    # Step 0: length gate. ``_sig`` and ``_pk`` are bare ByteString in the
    # builtin table and the type checker imposes no width, so both arrive
    # attacker-sized. Clamp them and remember whether they were the right size
    # -- see _c_emit_length_gate for why a clamp and not an abort. Without it
    # ``sig || junk`` verified identically to ``sig`` (fatal for any contract
    # using signature bytes as a nullifier), and a short ``sig`` aborted the
    # script outright.
    _c_emit_length_gate(t, "_pk", coord_bytes + 1, "_pk_len_ok")
    _c_emit_length_gate(t, "_sig", coord_bytes * 2, "_sig_len_ok")
    t.to_top("_pk_len_ok")
    t.to_top("_sig_len_ok")
    t.raw_block(["_pk_len_ok", "_sig_len_ok"], "_len_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

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
    t.push_tracked("_r_bytes", Dom.UNKNOWN)
    t.push_tracked("_s_bytes", Dom.UNKNOWN)

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

    # Step 2b: 1 <= r, s <= n-1. Without this an all-zero signature verifies for
    # any message under any pubkey -- see _c_emit_sig_range_gate.
    _c_emit_sig_range_gate(t, curve_n)

    # Step 3: Decompress pubkey. Also yields ``_dk_valid``: 0 when the pubkey
    # bytes do not decompress to a canonical on-curve point, which is ANDed into
    # the result below so such a key can never verify.
    _c_decompress_pub_key(
        t, "_pk", "_qx", "_qy",
        coord_bytes, reverse_bytes_fn,
        field_p, p_minus_2, curve_b, sqrt_exp,
    )

    # Collapse the three argument verdicts into one flag. Everything below then
    # carries a single item, as it did when ``_dk_valid`` was the only one.
    t.to_top("_len_ok")
    t.to_top("_range_ok")
    t.raw_block(["_len_ok", "_range_ok"], "_arg_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.to_top("_dk_valid")
    t.raw_block(["_arg_ok", "_dk_valid"], "_input_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

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

    # u1*G. G is a compile-time constant, so this half can use a fixed-base comb
    # -- one doubling and one add per COLUMN instead of per bit. u2*Q below
    # cannot: Q arrives in the witness.
    comb_ops = None
    if opts is not None and opts.fixed_base_comb and comb_curve is not None:
        comb_ops = _c_emit_comb_best(
            coord_bytes, reverse_bytes_fn, field_p, p_minus_2, curve_n, comb_curve, opts)

    if comb_ops is None:
        t.push_bytes("_G", g_point_data)
    t.to_top("_u1")

    # Stash items on altstack.
    # _input_ok goes DEEPEST -- the altstack is LIFO and it is popped last.
    t.to_top("_input_ok")
    t.to_alt()
    t.to_top("_r_save")
    t.to_alt()
    t.to_top("_u2")
    t.to_alt()
    t.to_top("_qy")
    t.to_alt()
    t.to_top("_qx")
    t.to_alt()

    # The multiply creates its own ECTracker and cannot see items below its
    # operands. Remove them from ours.
    t.pop_tracked()  # _u1
    if comb_ops is None:
        t.pop_tracked()  # _G

    if comb_ops is not None:
        for op in comb_ops:
            emit(op)
    else:
        _c_emit_mul(emit, coord_bytes, reverse_bytes_fn, field_p, p_minus_2,
                    curve_n, n_minus_2, opts)

    t.push_tracked("_R1_point", Dom.UNKNOWN)

    t.from_alt("_qx")
    t.from_alt("_qy")
    t.from_alt("_u2")

    t.to_top("_R1_point")
    t.to_alt()

    _c_compose_point(t, "_qx", "_qy", "_Q_point", coord_bytes, reverse_bytes_fn)

    t.to_top("_u2")

    t.pop_tracked()  # _u2
    t.pop_tracked()  # _Q_point

    _c_emit_mul(emit, coord_bytes, reverse_bytes_fn, field_p, p_minus_2,
                curve_n, n_minus_2, opts)
    t.push_tracked("_R2_point", Dom.UNKNOWN)

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

    # Restore r, then the argument verdict beneath it
    t.from_alt("_r_save")
    t.from_alt("_input_ok")

    t.to_top("_rx_mod_n")
    t.to_top("_r_save")
    t.raw_block(
        ["_rx_mod_n", "_r_save"],
        "_sig_ok",
        lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")),
    )

    # Arguments that were the wrong length, out of range, or did not decompress
    # to a canonical on-curve point can never verify, whatever the ladder made
    # of them.
    t.to_top("_input_ok")
    t.to_top("_sig_ok")
    t.raw_block(
        ["_input_ok", "_sig_ok"],
        "_result",
        lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")),
    )
    t.release_constant(POOL_GROUP_N)
    t.release_constant(POOL_FIELD_P)



# ===========================================================================
# Fixed-base comb (the base is a compile-time constant)
# ===========================================================================

def _c_emit_comb_mul_gen(
    emit: Callable,
    coord_bytes: int,
    reverse_bytes_fn: Callable,
    field_p: int,
    p_minus_2: int,
    curve_n: int,
    curve: CombCurve,
    w: int,
    opts: "EcCodegenOptions | None" = None,
) -> bool:
    """``k*G`` by a Lim-Lee comb, for a base known at compile time.

    The binary ladder runs one doubling and one conditional add per scalar BIT.
    A comb splits the scalar into ``w`` blocks of ``d`` bits and runs one
    doubling and one conditional add per COLUMN, so the round count falls from
    ``w*d`` to ``d`` at the price of a ``2^w - 1`` entry table -- which costs
    nothing to build here, because ``G`` is a constant. Measured optimum is w=3:
    the selection logic grows as ``2^w`` and overtakes the saving by w=5.

    SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
    accumulator equal to the addend, its negation, or the point at infinity.
    ``_c_build_jacobian_add_or_double_inline``'s comment justifies using it
    everywhere but the last step of the BINARY ladder by an interval argument
    over ``c_i mod n``, and insists that argument be re-derived by anything
    changing the offset or the iteration count. A comb changes both, so it is
    re-derived -- as executable interval arithmetic in ``comb_safe_rounds``,
    evaluated here. Rounds it cannot prove get the complete add-or-double form
    instead; nothing is assumed. For P-256 at w=3 it proves 81 of 86 rounds.

    The other half of that argument is that the accumulator never starts at
    infinity, which needs the first digit non-zero. ``comb_geometry`` searches
    for the scalar offset that guarantees it rather than reusing the ladder's
    hardcoded ``+3n`` -- right for P-256 at w=3 and WRONG for P-384.

    Stack in: [_k]. Stack out: [_result]. False when no geometry exists.
    """
    params = comb_geometry(w, curve)
    if params is None:
        return False
    d = params.d
    table = comb_table(w, d, curve)
    safe = comb_safe_rounds(params, curve)
    entries = (1 << w) - 1

    t = ECTracker(["_k"], emit, opts)
    t.pool_constant(POOL_FIELD_P, field_p)
    t.pool_constant(POOL_GROUP_N, curve_n)

    # k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so what
    # makes the interval argument apply at all; see _c_emit_scalar_reduce.
    t.to_top("_k")
    _c_emit_scalar_reduce(t, "_k", "_kr", curve_n)
    t.rename("_k")
    for i in range(params.offset_multiple):
        off = f"_off{i}"
        t.push_const(POOL_GROUP_N, curve_n, off)
        t.raw_block(["_k", off], "_k", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.set_domain("_k", Dom.NON_NEGATIVE)

    # Table, resident for the whole comb: picking an entry costs 2-3 bytes
    # against a 34-byte literal push, and every round reads all of them.
    for j in range(1, entries + 1):
        pt = table[j]
        t.push_big_int(f"_Tx{j}", pt.x)
        t.push_big_int(f"_Ty{j}", pt.y)
        t.set_domain(f"_Tx{j}", Dom.REDUCED)
        t.set_domain(f"_Ty{j}", Dom.REDUCED)

    # Round d-1 initialises the accumulator. The first digit is non-zero by
    # construction (comb_geometry), so this is a real point and never infinity.
    _comb_emit_select(t, d - 1, w, d)
    t.to_top("_flag")
    t.drop()
    t.to_top("ax")
    t.rename("jx")
    t.to_top("ay")
    t.rename("jy")
    t.push_int("jz", 1)
    t.set_domain("jz", Dom.REDUCED)

    for i in range(d - 2, -1, -1):
        _c_jacobian_double(t, field_p, p_minus_2)
        _comb_emit_select(t, i, w, d)

        # `_c_jacobian_add_affine_body` documents its layout as
        # [..., ax, ay, jx, jy, jz] and replaces the accumulator IN PLACE at the
        # top. The selection leaves ax/ay above jz, so restore the contract
        # before the branch -- otherwise the add arm would reorder the stack and
        # the empty else arm would not, leaving the two arms with different
        # layouts at OP_ENDIF.
        t.to_top("_flag")
        t.to_alt()
        t.to_top("jx")
        t.to_top("jy")
        t.to_top("jz")
        t.from_alt("_flag")

        t.pop_tracked()  # consumed by OP_IF
        add_ops: list = []
        if safe[i]:
            _c_build_jacobian_add_affine_inline(add_ops.append, t, field_p, p_minus_2)
        else:
            _c_build_jacobian_add_or_double_inline(add_ops.append, t, field_p, p_minus_2)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

        # The addend was selected fresh for this round; the add only copied it.
        t.to_top("ay")
        t.drop()
        t.to_top("ax")
        t.drop()

    _c_jacobian_to_affine(t, "_rx", "_ry", field_p, p_minus_2)

    for j in range(entries, 0, -1):
        t.to_top(f"_Ty{j}")
        t.drop()
        t.to_top(f"_Tx{j}")
        t.drop()
    t.to_top("_k")
    t.drop()

    _c_compose_point(t, "_rx", "_ry", "_result", coord_bytes, reverse_bytes_fn)
    t.release_constant(POOL_GROUP_N)
    t.release_constant(POOL_FIELD_P)
    return True


def _c_emit_comb_best(
    coord_bytes: int,
    reverse_bytes_fn: Callable,
    field_p: int,
    p_minus_2: int,
    curve_n: int,
    curve: CombCurve,
    opts: "EcCodegenOptions | None" = None,
):
    """Emit the cheapest comb over the candidate window widths.

    Each candidate is rendered in full and scored with the same byte-cost model
    the emitter is measured by, and the smallest wins.
    """
    best = None
    for w in (2, 3, 4):
        ops: list = []
        built = _c_emit_comb_mul_gen(
            ops.append, coord_bytes, reverse_bytes_fn, field_p, p_minus_2,
            curve_n, curve, w, opts)
        if not built:
            continue
        if best is None or estimate_script_bytes(ops) < estimate_script_bytes(best):
            best = ops
    return best


# ===========================================================================
# P-256 public API
# ===========================================================================

def emit_p256_add(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Add two P-256 points. Stack in: [pa, pb], out: [result]."""
    t = ECTracker(["_pa", "_pb"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P256_P)
    _c_decompose_point(t, "_pa", "px", "py", 32, _emit_reverse32)
    _c_decompose_point(t, "_pb", "qx", "qy", 32, _emit_reverse32)
    _c_affine_add(t, P256_P, P256_P_MINUS_2)
    _c_compose_point(t, "rx", "ry", "_result", 32, _emit_reverse32)
    t.release_constant(POOL_FIELD_P)


def emit_p256_mul(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """P-256 scalar multiplication. Stack in: [point, scalar], out: [result]."""
    _c_emit_mul(emit, 32, _emit_reverse32, P256_P, P256_P_MINUS_2, P256_N, P256_N_MINUS_2, opts)


def emit_p256_mul_gen(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """P-256 generator multiplication. Stack in: [scalar], out: [result]."""
    if opts is not None and opts.fixed_base_comb:
        ops = _c_emit_comb_best(32, _emit_reverse32, P256_P, P256_P_MINUS_2, P256_N, P256_COMB_CURVE, opts)
        if ops is not None:
            for op in ops:
                emit(op)
            return
    g_point = _bigint_to_n_bytes(P256_GX, 32) + _bigint_to_n_bytes(P256_GY, 32)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_p256_mul(emit, opts)


def emit_p256_negate(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Negate a P-256 point. Stack in: [point], out: [negated_point]."""
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P256_P)
    _c_decompose_point(t, "_pt", "_nx", "_ny", 32, _emit_reverse32)
    _c_push_field_p(t, "_fp", P256_P)
    _c_field_sub(t, "_fp", "_ny", "_neg_y", P256_P)
    _c_compose_point(t, "_nx", "_neg_y", "_result", 32, _emit_reverse32)
    t.release_constant(POOL_FIELD_P)


def emit_p256_on_curve(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Check if a P-256 point is on the curve (y^2 = x^3 - 3x + b mod p)."""
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P256_P)
    _c_decompose_point(t, "_pt", "_x", "_y", 32, _emit_reverse32)
    _c_emit_canonicity_guard(t, "_x", "_y", P256_P)

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
    t.raw_block(["_y2", "_rhs"], "_curve_eq", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))

    # on-curve = canonical AND curve-equation
    t.to_top("_canon")
    t.to_top("_curve_eq")
    t.raw_block(["_canon", "_curve_eq"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.release_constant(POOL_FIELD_P)


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


def emit_verify_ecdsa_p256(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
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
        comb_curve=P256_COMB_CURVE,
        opts=opts,
    )


# ===========================================================================
# P-384 public API
# ===========================================================================

def emit_p384_add(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Add two P-384 points. Stack in: [pa, pb], out: [result]."""
    t = ECTracker(["_pa", "_pb"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P384_P)
    _c_decompose_point(t, "_pa", "px", "py", 48, _emit_reverse48)
    _c_decompose_point(t, "_pb", "qx", "qy", 48, _emit_reverse48)
    _c_affine_add(t, P384_P, P384_P_MINUS_2)
    _c_compose_point(t, "rx", "ry", "_result", 48, _emit_reverse48)
    t.release_constant(POOL_FIELD_P)


def emit_p384_mul(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """P-384 scalar multiplication. Stack in: [point, scalar], out: [result]."""
    _c_emit_mul(emit, 48, _emit_reverse48, P384_P, P384_P_MINUS_2, P384_N, P384_N_MINUS_2, opts)


def emit_p384_mul_gen(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """P-384 generator multiplication. Stack in: [scalar], out: [result]."""
    if opts is not None and opts.fixed_base_comb:
        ops = _c_emit_comb_best(48, _emit_reverse48, P384_P, P384_P_MINUS_2, P384_N, P384_COMB_CURVE, opts)
        if ops is not None:
            for op in ops:
                emit(op)
            return
    g_point = _bigint_to_n_bytes(P384_GX, 48) + _bigint_to_n_bytes(P384_GY, 48)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_p384_mul(emit, opts)


def emit_p384_negate(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Negate a P-384 point. Stack in: [point], out: [negated_point]."""
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P384_P)
    _c_decompose_point(t, "_pt", "_nx", "_ny", 48, _emit_reverse48)
    _c_push_field_p(t, "_fp", P384_P)
    _c_field_sub(t, "_fp", "_ny", "_neg_y", P384_P)
    _c_compose_point(t, "_nx", "_neg_y", "_result", 48, _emit_reverse48)
    t.release_constant(POOL_FIELD_P)


def emit_p384_on_curve(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Check if a P-384 point is on the curve (y^2 = x^3 - 3x + b mod p)."""
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, P384_P)
    _c_decompose_point(t, "_pt", "_x", "_y", 48, _emit_reverse48)
    _c_emit_canonicity_guard(t, "_x", "_y", P384_P)

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
    t.raw_block(["_y2", "_rhs"], "_curve_eq", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))

    # on-curve = canonical AND curve-equation
    t.to_top("_canon")
    t.to_top("_curve_eq")
    t.raw_block(["_canon", "_curve_eq"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.release_constant(POOL_FIELD_P)


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


def emit_verify_ecdsa_p384(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
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
        comb_curve=P384_COMB_CURVE,
        opts=opts,
    )
