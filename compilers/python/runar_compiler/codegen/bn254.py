"""BN254 codegen -- BN254 elliptic curve field arithmetic and G1 point operations
for Bitcoin Script.

Follows the ec.py / koalabear.py pattern: self-contained module imported by
stack.py. Uses a BN254Tracker (mirrors ECTracker / KBTracker) for named stack
state tracking.

BN254 parameters:
    Field prime: p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    Curve order: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    Curve:       y^2 = x^3 + 3
    Generator:   G1 = (1, 2)

Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
Internal arithmetic uses Jacobian coordinates for scalar multiplication.

Direct port of ``compilers/go/codegen/bn254.go`` (Phase 1: Fp + G1 only).
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue

# ===========================================================================
# Constants
# ===========================================================================

# BN254 field prime.
BN254_P: int = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47

# p - 2, used for Fermat's little theorem modular inverse.
BN254_P_MINUS_2: int = BN254_P - 2

# BN254 curve order r.
BN254_R: int = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

# BN254 G1 generator.
BN254_GEN_X: int = 1
BN254_GEN_Y: int = 2


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _make_push_value(*, kind: str, **kwargs) -> "PushValue":
    from runar_compiler.codegen.stack import PushValue
    if "bytes_" in kwargs:
        kwargs["bytes_val"] = kwargs.pop("bytes_")
    return PushValue(kind=kind, **kwargs)


def _big_int_push(n: int) -> "PushValue":
    from runar_compiler.codegen.stack import big_int_push
    return big_int_push(n)


# Reuse EC byte reversal helper so composed points match the EC layout.
def _bn254_emit_reverse32(e: Callable) -> None:
    from runar_compiler.codegen.ec import _ec_emit_reverse32
    _ec_emit_reverse32(e)


# ===========================================================================
# BN254Tracker -- named stack state tracker (mirrors ECTracker)
# ===========================================================================

class BN254Tracker:
    """Tracks named stack positions and emits StackOps for BN254 codegen."""

    def __init__(self, init: list[str], emit: Callable[["StackOp"], None]) -> None:
        self.nm: list[str] = list(init)
        self.e = emit
        self._prime_cache_active: bool = False

    # -----------------------------------------------------------------------
    # Stack primitives
    # -----------------------------------------------------------------------

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"BN254Tracker: '{name}' not on stack {self.nm}")

    def push_bytes(self, n: str, v: bytes) -> None:
        self.e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=v)))
        self.nm.append(n)

    def push_big_int(self, n: str, v: int) -> None:
        self.e(_make_stack_op(op="push", value=_make_push_value(kind="bigint", big_int=v)))
        self.nm.append(n)

    def push_int(self, n: str, v: int) -> None:
        self.e(_make_stack_op(op="push", value=_big_int_push(v)))
        self.nm.append(n)

    def dup(self, n: str) -> None:
        self.e(_make_stack_op(op="dup"))
        self.nm.append(n)

    def drop(self) -> None:
        self.e(_make_stack_op(op="drop"))
        if self.nm:
            self.nm.pop()

    def nip(self) -> None:
        self.e(_make_stack_op(op="nip"))
        L = len(self.nm)
        if L >= 2:
            self.nm[L - 2:L] = [self.nm[L - 1]]

    def over(self, n: str) -> None:
        self.e(_make_stack_op(op="over"))
        self.nm.append(n)

    def swap(self) -> None:
        self.e(_make_stack_op(op="swap"))
        L = len(self.nm)
        if L >= 2:
            self.nm[L - 1], self.nm[L - 2] = self.nm[L - 2], self.nm[L - 1]

    def rot(self) -> None:
        self.e(_make_stack_op(op="rot"))
        L = len(self.nm)
        if L >= 3:
            r = self.nm[L - 3]
            del self.nm[L - 3]
            self.nm.append(r)

    def op(self, code: str) -> None:
        self.e(_make_stack_op(op="opcode", code=code))

    def roll(self, d: int) -> None:
        if d == 0:
            return
        if d == 1:
            self.swap()
            return
        if d == 2:
            self.rot()
            return
        self.e(_make_stack_op(op="push", value=_big_int_push(d)))
        self.nm.append("")
        self.e(_make_stack_op(op="roll", depth=d))
        self.nm.pop()  # pop the push placeholder
        idx = len(self.nm) - 1 - d
        r = self.nm[idx]
        del self.nm[idx]
        self.nm.append(r)

    def pick(self, d: int, n: str) -> None:
        if d == 0:
            self.dup(n)
            return
        if d == 1:
            self.over(n)
            return
        self.e(_make_stack_op(op="push", value=_big_int_push(d)))
        self.nm.append("")
        self.e(_make_stack_op(op="pick", depth=d))
        self.nm.pop()  # pop the push placeholder
        self.nm.append(n)

    def to_top(self, name: str) -> None:
        self.roll(self.find_depth(name))

    def copy_to_top(self, name: str, n: str) -> None:
        self.pick(self.find_depth(name), n)

    def to_alt(self) -> None:
        self.op("OP_TOALTSTACK")
        if self.nm:
            self.nm.pop()

    def from_alt(self, n: str) -> None:
        self.op("OP_FROMALTSTACK")
        self.nm.append(n)

    def rename(self, n: str) -> None:
        if self.nm:
            self.nm[-1] = n

    def raw_block(
        self,
        consume: list[str],
        produce: str,
        fn: Callable[[Callable[["StackOp"], None]], None],
    ) -> None:
        """Emit raw opcodes; tracker only records net stack effect.

        *produce* = "" means no output pushed.
        """
        for _ in consume:
            if self.nm:
                self.nm.pop()
        fn(self.e)
        if produce:
            self.nm.append(produce)

    # -----------------------------------------------------------------------
    # Prime cache helpers (alt-stack caching for the BN254 field prime)
    # -----------------------------------------------------------------------

    def push_prime_cache(self) -> None:
        """Push the BN254 field prime to the alt-stack for caching.

        Subsequent field operations will use the cached prime instead of
        pushing fresh 34-byte literals, saving ~93 bytes per Fp mod.
        """
        self.push_big_int("_pcache_p", BN254_P)
        self.op("OP_TOALTSTACK")
        if self.nm:
            self.nm.pop()
        self._prime_cache_active = True

    def pop_prime_cache(self) -> None:
        """Remove the cached field prime from the alt-stack."""
        self.op("OP_FROMALTSTACK")
        self.nm.append("_pcache_cleanup")
        self.drop()
        self._prime_cache_active = False


# ===========================================================================
# Field arithmetic helpers
# ===========================================================================

def _bn254_push_field_p(t: BN254Tracker, name: str) -> None:
    t.push_big_int(name, BN254_P)


def _bn254_field_mod(t: BN254Tracker, a_name: str, result_name: str) -> None:
    """Reduce TOS mod p, ensuring non-negative result.

    Pattern: (a % p + p) % p
    Uses alt-stack cached prime when available.
    """
    t.to_top(a_name)
    if t._prime_cache_active:
        def _fn(e: Callable) -> None:
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            # [a, p] -> TUCK -> [p, a, p]
            e(_make_stack_op(op="opcode", code="OP_TUCK"))
            # [p, a, p] -> MOD -> [p, a%p]
            e(_make_stack_op(op="opcode", code="OP_MOD"))
            # [p, a%p] -> OVER -> [p, a%p, p]
            e(_make_stack_op(op="over"))
            # [p, a%p, p] -> ADD -> [p, a%p+p]
            e(_make_stack_op(op="opcode", code="OP_ADD"))
            # [p, a%p+p] -> SWAP -> [a%p+p, p]
            e(_make_stack_op(op="swap"))
            # [a%p+p, p] -> MOD -> [(a%p+p)%p]
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name], result_name, _fn)
    else:
        _bn254_push_field_p(t, "_fmod_p")
        def _fn_nocache(e: Callable) -> None:
            e(_make_stack_op(op="opcode", code="OP_TUCK"))
            e(_make_stack_op(op="opcode", code="OP_MOD"))
            e(_make_stack_op(op="over"))
            e(_make_stack_op(op="opcode", code="OP_ADD"))
            e(_make_stack_op(op="swap"))
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name, "_fmod_p"], result_name, _fn_nocache)


def _bn254_field_mod_positive(t: BN254Tracker, a_name: str, result_name: str) -> None:
    """Reduce a non-negative value modulo p using a single OP_MOD.

    SAFETY: Only use when the input is guaranteed non-negative (e.g. after
    OP_MUL of two non-negative values, or OP_ADD of non-negative values).
    """
    t.to_top(a_name)
    if t._prime_cache_active:
        def _fn(e: Callable) -> None:
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name], result_name, _fn)
    else:
        _bn254_push_field_p(t, "_fmodp_p")
        t.raw_block([a_name, "_fmodp_p"], result_name,
                    lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))


def _bn254_field_add(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a + b) mod p.

    Both operands are non-negative field elements, so the sum is non-negative;
    use the single-OP_MOD (positive) reduction.
    """
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fadd_sum",
                lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    _bn254_field_mod_positive(t, "_fadd_sum", result_name)


def _bn254_field_add_unreduced(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute a + b WITHOUT modular reduction."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))


def _bn254_field_sub_unreduced(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute a - b WITHOUT modular reduction (result may be negative)."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))


def _bn254_field_mul_unreduced(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute a * b WITHOUT modular reduction."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))


def _bn254_field_sub(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a - b) mod p (non-negative).

    Computes (a - b + p) mod p via a single fused OP_MOD. Works for a >= 0
    (including unreduced sums) and b in [0, p-1]. Fetches p once and reuses
    it for both the add and the mod when the prime cache is active.
    """
    t.to_top(a_name)
    t.to_top(b_name)
    if t._prime_cache_active:
        def _fn(e: Callable) -> None:
            e(_make_stack_op(op="opcode", code="OP_SUB"))  # [diff]
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            # [diff, p] -> TUCK -> [p, diff, p]
            e(_make_stack_op(op="opcode", code="OP_TUCK"))
            # [p, diff, p] -> ADD -> [p, diff+p]
            e(_make_stack_op(op="opcode", code="OP_ADD"))
            # [p, diff+p] -> SWAP -> [diff+p, p]
            e(_make_stack_op(op="swap"))
            # [diff+p, p] -> MOD -> [(diff+p)%p]
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name, b_name], result_name, _fn)
    else:
        t.raw_block([a_name, b_name], "_fsub_diff",
                    lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))
        _bn254_field_mod(t, "_fsub_diff", result_name)


def _bn254_field_mul(t: BN254Tracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a * b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fmul_prod",
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    _bn254_field_mod_positive(t, "_fmul_prod", result_name)


def _bn254_field_sqr(t: BN254Tracker, a_name: str, result_name: str) -> None:
    """Compute (a * a) mod p."""
    t.copy_to_top(a_name, "_fsqr_copy")
    _bn254_field_mul(t, a_name, "_fsqr_copy", result_name)


def _bn254_field_mul_const(t: BN254Tracker, a_name: str, c: int, result_name: str) -> None:
    """Compute (a * c) mod p where c is a small positive constant.

    Uses OP_2MUL when c == 2, otherwise pushes the constant and multiplies.
    Both inputs are non-negative, so single-OP_MOD reduction is safe.
    """
    t.to_top(a_name)

    def _fmc_body(e: Callable) -> None:
        if c == 2:
            e(_make_stack_op(op="opcode", code="OP_2MUL"))
        else:
            e(_make_stack_op(op="push", value=_big_int_push(c)))
            e(_make_stack_op(op="opcode", code="OP_MUL"))

    t.raw_block([a_name], "_bn_mc", _fmc_body)
    _bn254_field_mod_positive(t, "_bn_mc", result_name)


def _bn254_field_neg(t: BN254Tracker, a_name: str, result_name: str) -> None:
    """Compute (p - a) mod p.

    Since a in [0, p-1], p - a is always in [1, p]. Fetches p once and DUPs
    it: one copy for the subtraction, one for the mod.
    """
    t.to_top(a_name)
    if t._prime_cache_active:
        def _fn(e: Callable) -> None:
            # [a]
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
            # [a, p] -> DUP -> [a, p, p]
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            # [a, p, p] -> ROT -> [p, p, a]
            e(_make_stack_op(op="rot"))
            # [p, p, a] -> SUB -> [p, p-a]
            e(_make_stack_op(op="opcode", code="OP_SUB"))
            # [p, p-a] -> SWAP -> [p-a, p]
            e(_make_stack_op(op="swap"))
            # [p-a, p] -> MOD -> [(p-a)%p]
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name], result_name, _fn)
    else:
        _bn254_push_field_p(t, "_fneg_p")
        def _fn_nocache(e: Callable) -> None:
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="rot"))
            e(_make_stack_op(op="opcode", code="OP_SUB"))
            e(_make_stack_op(op="swap"))
            e(_make_stack_op(op="opcode", code="OP_MOD"))
        t.raw_block([a_name, "_fneg_p"], result_name, _fn_nocache)


def _bn254_field_inv(t: BN254Tracker, a_name: str, result_name: str) -> None:
    """Compute a^(p-2) mod p via square-and-multiply (Fermat's little theorem).

    BN254 p is a 254-bit prime. Initializes result = a (processing the MSB
    bit 253 implicitly), then iterates bits 252 down to 0 (253 squarings).
    """
    # result = a implicitly handles bit 253 (MSB of p-2, always set)
    t.copy_to_top(a_name, "_inv_r")

    # Process bits 252 down to 0 (253 iterations, one squaring each)
    p_minus_2 = BN254_P_MINUS_2
    for i in range(252, -1, -1):
        _bn254_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")

        if (p_minus_2 >> i) & 1:
            t.copy_to_top(a_name, "_inv_a")
            _bn254_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")

    # Clean up original input and rename result
    t.to_top(a_name)
    t.drop()
    t.to_top("_inv_r")
    t.rename(result_name)


# ===========================================================================
# Point decompose / compose
# ===========================================================================

def _bn254_decompose_point(t: BN254Tracker, point_name: str, x_name: str, y_name: str) -> None:
    """Decompose a 64-byte Point into (x_num, y_num) on stack.

    Consumes *point_name*, produces *x_name* and *y_name*.
    """
    t.to_top(point_name)
    # R-141: gate the WIDTH here, so every consumer that decomposes a BN254
    # Point inherits the check -- the same placement CL-BUG-095 chose for
    # ec.py's decompose. Without it OP_SPLIT at 32 discards whatever follows
    # byte 64, so bn254G1OnCurve(G || 0xff) returned TRUE. ABORTING form:
    # emit_bn254_g1_on_curve must stay TOTAL, so it clamps and flags the length
    # BEFORE calling this.
    def _split(e: Callable) -> None:
        from runar_compiler.codegen.ec import emit_point_len_verify
        emit_point_len_verify(e, 64)
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
    t.raw_block([point_name], "", _split)
    # Manually track the two new items
    t.nm.append("_dp_xb")
    t.nm.append("_dp_yb")

    # Convert y_bytes (on top) to num
    def _convert_y(e: Callable) -> None:
        _bn254_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_yb"], y_name, _convert_y)

    # Convert x_bytes to num
    t.to_top("_dp_xb")
    def _convert_x(e: Callable) -> None:
        _bn254_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_xb"], x_name, _convert_x)

    # Stack: [yName, xName] -- swap to standard order [xName, yName]
    t.swap()


def _bn254_compose_point(t: BN254Tracker, x_name: str, y_name: str, result_name: str) -> None:
    """Compose (x_num, y_num) into a 64-byte Point.

    Consumes *x_name* and *y_name*, produces *result_name*.

    IMPORTANT: Callers must ensure x and y are valid field elements in
    [0, p-1]. This function does not validate input range.
    """
    # Convert x to 32-byte big-endian
    t.to_top(x_name)
    def _convert_x(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(33)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        # Drop the sign byte -- split at 32, keep left
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        _bn254_emit_reverse32(e)
    t.raw_block([x_name], "_cp_xb", _convert_x)

    # Convert y to 32-byte big-endian
    t.to_top(y_name)
    def _convert_y(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(33)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        _bn254_emit_reverse32(e)
    t.raw_block([y_name], "_cp_yb", _convert_y)

    # Cat: x_be || y_be (x is below y after the two to_top calls)
    t.to_top("_cp_xb")
    t.to_top("_cp_yb")
    t.raw_block(["_cp_xb", "_cp_yb"], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_CAT")))


# ===========================================================================
# Point at infinity for the bn254G1Add builtin
# ===========================================================================

def _bn254_g1_infinity_flag(t: BN254Tracker) -> None:
    """Compute `_notinf`, 0 exactly when P == -Q and 1 otherwise.

    Reads px/py/qx/qy WITHOUT consuming them. Call it before
    _bn254_g1_affine_add; apply the result with _bn254_g1_mask_infinity after.

    P + (-P) is the point at infinity, which affine x||y cannot represent.
    This codegen already has an encoding for O -- the ALL-ZERO blob, which is
    what bn254G1ScalarMul returns for k = 0 mod r and what secp256k1 and both
    NIST curves return for their own P + (-P). bn254G1Add is a general
    contract-callable builtin, so it owes callers the same answer rather than
    the off-curve blob the unified slope produces there (py + qy == 0 and the
    field inverse is Fermat, so inv(0) = 0). O is not on the curve
    (0^2 != 0^3 + 3), so the documented assert(bn254G1OnCurve(r)) idiom still
    rejects the result.

    THE PREDICATE IS px == qx AND py != qy, NOT a zero denominator. BN254 has
    j-invariant 0 with p = 1 mod 3, so F_p holds a primitive cube root of
    unity w and Q = (w*px, -py) is an ordinary point that also zeroes py + qy
    while P + Q is an ordinary point, not O. Masking on the denominator would
    answer "infinity" there: plausible and wrong -- the exact failure mode
    03f50d48 introduced on the NIST curves and f16790a9 had to undo. Testing
    px == qx ALONE would be wrong in the other direction: it would swallow
    doubling.

    Deliberately NOT inside _bn254_g1_affine_add: the Groth16 MSM bind shares
    that helper and keeps its fail-closed behaviour and its bytes unchanged.

    Byte-identical to `bn254G1InfinityFlag` in compilers/go/codegen/bn254.go.
    """
    t.copy_to_top("px", "_inf_px")
    t.copy_to_top("qx", "_inf_qx")
    t.raw_block(["_inf_px", "_inf_qx"], "_xeq",
                lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    t.copy_to_top("py", "_inf_py")
    t.copy_to_top("qy", "_inf_qy")
    t.raw_block(["_inf_py", "_inf_qy"], "_yeq",
                lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
    # cond = xeq AND yeq: 1 when doubling.
    t.copy_to_top("_xeq", "_xeq_c")
    t.to_top("_yeq")
    t.raw_block(["_xeq_c", "_yeq"], "_cond",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
    # points are not equal, i.e. exactly the P == -Q case.
    def _notinf_fn(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_SUB"))
        e(_make_stack_op(op="opcode", code="OP_NOT"))

    t.to_top("_xeq")
    t.to_top("_cond")
    t.raw_block(["_xeq", "_cond"], "_notinf", _notinf_fn)


def _bn254_g1_mask_infinity(t: BN254Tracker) -> None:
    """Zero rx and ry when `_notinf` is 0, consuming it.

    The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
    and notinf is 0 or 1, so the product is canonical either way.
    """
    t.to_top("rx")
    t.copy_to_top("_notinf", "_notinf_x")
    t.raw_block(["rx", "_notinf_x"], "rx",
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    t.to_top("ry")
    t.to_top("_notinf")
    t.raw_block(["ry", "_notinf"], "ry",
                lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))


# ===========================================================================
# Affine point addition (for bn254G1Add)
# ===========================================================================

def _bn254_g1_affine_add(t: BN254Tracker) -> None:
    """Perform affine point addition on BN254 G1.

    Uses the unified slope formula
        s = (px^2 + px*qx + qx^2) / (py + qy)
    which handles both P != Q and the doubling case P == Q on y^2 = x^3 + b.
    The remaining zero-denominator input (py + qy == 0) is handled by the
    caller: emit_bn254_g1_add masks P == -Q to the all-zero point at infinity
    (see _bn254_g1_infinity_flag); the Groth16 MSM path shares this helper
    unmasked and stays fail-closed.

    Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four
    inputs.
    """
    # s_num = px^2 + px*qx + qx^2
    t.copy_to_top("px", "_px_sq_in")
    _bn254_field_sqr(t, "_px_sq_in", "_px_sq")
    t.copy_to_top("px", "_px_m")
    t.copy_to_top("qx", "_qx_m")
    _bn254_field_mul(t, "_px_m", "_qx_m", "_px_qx")
    t.copy_to_top("qx", "_qx_sq_in")
    _bn254_field_sqr(t, "_qx_sq_in", "_qx_sq")
    _bn254_field_add(t, "_px_sq", "_px_qx", "_s_num_tmp")
    _bn254_field_add(t, "_s_num_tmp", "_qx_sq", "_s_num")

    # s_den = py + qy
    t.copy_to_top("py", "_py_a")
    t.copy_to_top("qy", "_qy_a")
    _bn254_field_add(t, "_py_a", "_qy_a", "_s_den")

    # s = s_num / s_den mod p
    _bn254_field_inv(t, "_s_den", "_s_den_inv")
    _bn254_field_mul(t, "_s_num", "_s_den_inv", "_s")

    # rx = s^2 - px - qx mod p
    t.copy_to_top("_s", "_s_keep")
    _bn254_field_sqr(t, "_s", "_s2")
    t.copy_to_top("px", "_px2")
    _bn254_field_sub(t, "_s2", "_px2", "_rx1")
    t.copy_to_top("qx", "_qx2")
    _bn254_field_sub(t, "_rx1", "_qx2", "rx")

    # ry = s * (px - rx) - py mod p
    t.copy_to_top("px", "_px3")
    t.copy_to_top("rx", "_rx2")
    _bn254_field_sub(t, "_px3", "_rx2", "_px_rx")
    _bn254_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
    t.copy_to_top("py", "_py2")
    _bn254_field_sub(t, "_s_px_rx", "_py2", "ry")

    # Clean up original points
    t.to_top("px")
    t.drop()
    t.to_top("py")
    t.drop()
    t.to_top("qx")
    t.drop()
    t.to_top("qy")
    t.drop()


# ===========================================================================
# Jacobian point operations (for bn254G1ScalarMul)
# ===========================================================================

def _bn254_g1_jacobian_double(t: BN254Tracker) -> None:
    """Perform Jacobian point doubling (a=0 for BN254).

    Formulas (a=0 since y^2 = x^3 + b):
        A  = Y^2
        B  = 4*X*A
        C  = 8*A^2
        D  = 3*X^2
        X' = D^2 - 2*B
        Y' = D*(B - X') - C
        Z' = 2*Y*Z

    Expects jx, jy, jz on tracker. Replaces with updated values.
    """
    # Save copies of jx, jy, jz for later use
    t.copy_to_top("jy", "_jy_save")
    t.copy_to_top("jx", "_jx_save")
    t.copy_to_top("jz", "_jz_save")

    # A = jy^2
    _bn254_field_sqr(t, "jy", "_A")

    # B = 4 * jx * A
    t.copy_to_top("_A", "_A_save")
    _bn254_field_mul(t, "jx", "_A", "_xA")
    t.push_int("_four", 4)
    _bn254_field_mul(t, "_xA", "_four", "_B")

    # C = 8 * A^2
    _bn254_field_sqr(t, "_A_save", "_A2")
    t.push_int("_eight", 8)
    _bn254_field_mul(t, "_A2", "_eight", "_C")

    # D = 3 * X^2
    _bn254_field_sqr(t, "_jx_save", "_x2")
    t.push_int("_three", 3)
    _bn254_field_mul(t, "_x2", "_three", "_D")

    # nx = D^2 - 2*B
    t.copy_to_top("_D", "_D_save")
    t.copy_to_top("_B", "_B_save")
    _bn254_field_sqr(t, "_D", "_D2")
    t.copy_to_top("_B", "_B1")
    _bn254_field_mul_const(t, "_B1", 2, "_2B")
    _bn254_field_sub(t, "_D2", "_2B", "_nx")

    # ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy")
    _bn254_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
    _bn254_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
    _bn254_field_sub(t, "_D_B_nx", "_C", "_ny")

    # nz = 2 * Y * Z
    _bn254_field_mul(t, "_jy_save", "_jz_save", "_yz")
    _bn254_field_mul_const(t, "_yz", 2, "_nz")

    # Clean up leftovers: _B and old jz (only copied, never consumed)
    t.to_top("_B")
    t.drop()
    t.to_top("jz")
    t.drop()
    t.to_top("_nx")
    t.rename("jx")
    t.to_top("_ny")
    t.rename("jy")
    t.to_top("_nz")
    t.rename("jz")


def _bn254_g1_jacobian_to_affine(t: BN254Tracker, rx_name: str, ry_name: str) -> None:
    """Convert Jacobian to affine coordinates.

    Consumes jx, jy, jz; produces *rx_name*, *ry_name*.
    """
    _bn254_field_inv(t, "jz", "_zinv")
    t.copy_to_top("_zinv", "_zinv_keep")
    _bn254_field_sqr(t, "_zinv", "_zinv2")
    t.copy_to_top("_zinv2", "_zinv2_keep")
    _bn254_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3")
    _bn254_field_mul(t, "jx", "_zinv2_keep", rx_name)
    _bn254_field_mul(t, "jy", "_zinv3", ry_name)


# ===========================================================================
# Jacobian mixed addition (P_jacobian + Q_affine)
# ===========================================================================

def _bn254_build_jacobian_add_affine_standard(it: BN254Tracker) -> None:
    """Emit the standard Jacobian mixed-add sequence.

    WARNING: this fails (H = 0 in the chord formula) when the Jacobian
    accumulator equals the affine base point in affine form. Callers must
    guard against that case; see _bn254_build_jacobian_add_affine_inline for
    the complete doubling-safe wrapper used by scalar multiplication.

    Consumes jx, jy, jz on the tracker (ax, ay read via copy-to-top) and
    produces replacement jx, jy, jz.
    """
    # Save copies of values that get consumed but are needed later
    it.copy_to_top("jz", "_jz_for_z1cu")   # consumed by Z1sq, needed for Z1cu
    it.copy_to_top("jz", "_jz_for_z3")     # needed for Z3
    it.copy_to_top("jy", "_jy_for_y3")     # consumed by R, needed for Y3
    it.copy_to_top("jx", "_jx_for_u1h2")   # consumed by H, needed for U1H2

    # Z1sq = jz^2
    _bn254_field_sqr(it, "jz", "_Z1sq")

    # Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
    _bn254_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

    # U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c")
    _bn254_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

    # S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c")
    _bn254_field_mul(it, "_ay_c", "_Z1cu", "_S2")

    # H = U2 - jx
    _bn254_field_sub(it, "_U2", "jx", "_H")

    # R = S2 - jy
    _bn254_field_sub(it, "_S2", "jy", "_R")

    # Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
    it.copy_to_top("_H", "_H_for_h3")
    it.copy_to_top("_H", "_H_for_z3")

    # H2 = H^2
    _bn254_field_sqr(it, "_H", "_H2")

    # Save H2 for U1H2
    it.copy_to_top("_H2", "_H2_for_u1h2")

    # H3 = H_for_h3 * H2
    _bn254_field_mul(it, "_H_for_h3", "_H2", "_H3")

    # U1H2 = _jx_for_u1h2 * H2_for_u1h2
    _bn254_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

    # Save R, U1H2, H3 for Y3 computation
    it.copy_to_top("_R", "_R_for_y3")
    it.copy_to_top("_U1H2", "_U1H2_for_y3")
    it.copy_to_top("_H3", "_H3_for_y3")

    # X3 = R^2 - H3 - 2*U1H2
    _bn254_field_sqr(it, "_R", "_R2")
    _bn254_field_sub(it, "_R2", "_H3", "_x3_tmp")
    _bn254_field_mul_const(it, "_U1H2", 2, "_2U1H2")
    _bn254_field_sub(it, "_x3_tmp", "_2U1H2", "_X3")

    # Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c")
    _bn254_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
    _bn254_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
    _bn254_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
    _bn254_field_sub(it, "_r_tmp", "_jy_h3", "_Y3")

    # Z3 = _jz_for_z3 * _H_for_z3
    _bn254_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

    # Rename results to jx/jy/jz
    it.to_top("_X3")
    it.rename("jx")
    it.to_top("_Y3")
    it.rename("jy")
    it.to_top("_Z3")
    it.rename("jz")


def _bn254_build_jacobian_add_affine_inline(e: Callable, t: BN254Tracker,
                                           strict: bool) -> None:
    """Build doubling-safe Jacobian mixed-add ops for use inside OP_IF.

    Uses an inner BN254Tracker to leverage the field arithmetic helpers.

    Stack layout: [..., ax, ay, _k, jx, jy, jz]
    After:        [..., ax, ay, _k, jx', jy', jz']

    The standard Jacobian mixed-add formula divides by H = ax*jz^2 - jx,
    which is 0 when the accumulator's affine image equals the base point.
    To handle that case, we check H == 0 at runtime and delegate to Jacobian
    doubling of (jx, jy, jz) when it fires; otherwise the standard mixed-add
    runs.
    """
    # Create inner tracker with cloned stack state
    it = BN254Tracker(list(t.nm), e)
    # Propagate prime cache state: cached prime on alt-stack persists across
    # IF/ELSE/ENDIF boundaries.
    it._prime_cache_active = t._prime_cache_active

    # ------------------------------------------------------------------
    # Doubling-case detection: H = ax*jz^2 - jx == 0 ?
    # ------------------------------------------------------------------
    # Compute U2 = ax * jz^2 without consuming jx, jy, or jz, then compare
    # against a fresh copy of jx. Consumes only the copies.
    it.copy_to_top("jz", "_jz_chk_in")
    _bn254_field_sqr(it, "_jz_chk_in", "_jz_chk_sq")
    if strict:
        # Z1sq is consumed by U2 below; keep a copy for Z1cu.
        it.copy_to_top("_jz_chk_sq", "_jz_chk_sq_keep")
    it.copy_to_top("ax", "_ax_chk_copy")
    _bn254_field_mul(it, "_ax_chk_copy", "_jz_chk_sq", "_u2_chk")
    it.copy_to_top("jx", "_jx_chk_copy")
    it.raw_block(["_u2_chk", "_jx_chk_copy"], "_h_is_zero",
                 lambda e_: e_(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))

    cond_name = "_h_is_zero"
    if strict:
        # R = ay*jz^3 - jy == 0 ? Only H == 0 AND R == 0 means the two
        # operands are the SAME point; H == 0 with R != 0 means they are
        # negatives, whose sum is O -- and the standard mixed-add already
        # answers that correctly, with Z3 = jz*H = 0 flowing through the
        # Fermat inverse to the all-zero point.
        it.copy_to_top("jz", "_jz_chk_for_cu")
        _bn254_field_mul(it, "_jz_chk_for_cu", "_jz_chk_sq_keep", "_z1cu_chk")
        it.copy_to_top("ay", "_ay_chk_copy")
        _bn254_field_mul(it, "_ay_chk_copy", "_z1cu_chk", "_s2_chk")
        it.copy_to_top("jy", "_jy_chk_copy")
        it.raw_block(["_s2_chk", "_jy_chk_copy"], "_r_is_zero",
                     lambda e_: e_(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
        it.to_top("_h_is_zero")
        it.to_top("_r_is_zero")
        it.raw_block(["_h_is_zero", "_r_is_zero"], "_dbl_cond",
                     lambda e_: e_(_make_stack_op(op="opcode", code="OP_BOOLAND")))
        cond_name = "_dbl_cond"

    # Move the condition to top so OP_IF can consume it.
    it.to_top(cond_name)
    it.nm.pop()  # consumed by IF

    # ------------------------------------------------------------------
    # Gather doubling-branch ops
    # ------------------------------------------------------------------
    doubling_ops: list = []
    doubling_emit = lambda op: doubling_ops.append(op)
    doubling_tracker = BN254Tracker(list(it.nm), doubling_emit)
    doubling_tracker._prime_cache_active = it._prime_cache_active
    _bn254_g1_jacobian_double(doubling_tracker)

    # ------------------------------------------------------------------
    # Gather standard-add-branch ops
    # ------------------------------------------------------------------
    add_ops: list = []
    add_emit = lambda op: add_ops.append(op)
    add_tracker = BN254Tracker(list(it.nm), add_emit)
    add_tracker._prime_cache_active = it._prime_cache_active
    _bn254_build_jacobian_add_affine_standard(add_tracker)

    # Both branches leave (jx, jy, jz) replacing the originals with the
    # same stack layout.
    it.e(_make_stack_op(op="if", then=doubling_ops, else_=add_ops))
    it.nm = doubling_tracker.nm


# ===========================================================================
# G1 point negation
# ===========================================================================

def _bn254_g1_negate(t: BN254Tracker, point_name: str, result_name: str) -> None:
    """Negate a point: (x, p - y)."""
    _bn254_decompose_point(t, point_name, "_nx", "_ny")
    # R-141: _bn254_compose_point below is documented as requiring [0, p-1] and
    # does not check, so without this the negation of a non-canonical point
    # re-emitted its x half verbatim.
    _bn254_emit_coord_canon_verify(t, "_nx", "_ny")
    _bn254_field_neg(t, "_ny", "_neg_y")
    _bn254_compose_point(t, "_nx", "_neg_y", result_name)


# ===========================================================================
# Public emit functions -- entry points called from stack.py
# ===========================================================================

def emit_bn254_field_add(emit: Callable[["StackOp"], None]) -> None:
    """BN254 field addition.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a + b) mod p]
    """
    t = BN254Tracker(["a", "b"], emit)
    t.push_prime_cache()
    _bn254_field_add(t, "a", "b", "result")
    t.pop_prime_cache()


def emit_bn254_field_sub(emit: Callable[["StackOp"], None]) -> None:
    """BN254 field subtraction.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a - b) mod p]
    """
    t = BN254Tracker(["a", "b"], emit)
    t.push_prime_cache()
    _bn254_field_sub(t, "a", "b", "result")
    t.pop_prime_cache()


def emit_bn254_field_mul(emit: Callable[["StackOp"], None]) -> None:
    """BN254 field multiplication.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a * b) mod p]
    """
    t = BN254Tracker(["a", "b"], emit)
    t.push_prime_cache()
    _bn254_field_mul(t, "a", "b", "result")
    t.pop_prime_cache()


def emit_bn254_field_inv(emit: Callable[["StackOp"], None]) -> None:
    """BN254 field multiplicative inverse.

    Stack in:  [..., a]
    Stack out: [..., a^(p-2) mod p]
    """
    t = BN254Tracker(["a"], emit)
    t.push_prime_cache()
    _bn254_field_inv(t, "a", "result")
    t.pop_prime_cache()


def emit_bn254_field_neg(emit: Callable[["StackOp"], None]) -> None:
    """BN254 field negation.

    Stack in:  [..., a]
    Stack out: [..., (p - a) mod p]
    """
    t = BN254Tracker(["a"], emit)
    t.push_prime_cache()
    _bn254_field_neg(t, "a", "result")
    t.pop_prime_cache()


def _bn254_emit_point_length_gate(t: BN254Tracker, name: str, want: int, flag_name: str) -> None:
    """R-141, CLAMPING form -- the BN254 twin of ec.py's point length gate.

    Leaves [flag, clamped] on the tracker. Used by emit_bn254_g1_on_curve,
    whose job is to answer "is this an acceptable point?" over untrusted bytes:
    for a wrong-length blob the correct answer is FALSE, not an aborted script.
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
    t.nm.append(flag_name)
    t.nm.append(name)


def _bn254_emit_coord_canon_verify(t: BN254Tracker, x_name: str, y_name: str) -> None:
    """R-141 -- a BN254 G1 Point's coordinates must be FIELD ELEMENTS, aborting.

    The direct analogue of ec.py's R-117 gate, with the placement re-derived for
    this curve. _bn254_decompose_point BIN2NUMs each half as an UNSIGNED integer,
    so any value fitting 32 bytes is accepted; p is ~2^253.6, so x + p < 2^256
    for EVERY x < p -- unlike secp256k1, the alias exists for every point on the
    curve. Measured before this gate, with G = (1, 2): bn254G1OnCurve((1+p)||2),
    bn254G1OnCurve(1||(2+p)) and bn254G1OnCurve(G||0xff) all returned 1.

    The value builtins abort for a DIFFERENT reason than secp256k1's did: BN254's
    adder is not fooled into a wrong answer (bn254G1Add(G, (1+p)||2) returns the
    correct 2G, because the infinity flag reduces before it compares), but
    _bn254_compose_point is documented as requiring [0, p-1] and not checking,
    and _bn254_g1_negate handed it the raw decomposed x -- a value builtin
    PRODUCING something that is not a point.

    Deliberately NOT folded into _bn254_decompose_point: that helper also runs
    inside emit_bn254_g1_on_curve, which must return FALSE rather than abort.
    """
    t.copy_to_top(x_name, "_cc_x")
    _bn254_push_field_p(t, "_cc_px")
    t.raw_block(["_cc_x", "_cc_px"], "_cc_xok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.copy_to_top(y_name, "_cc_y")
    _bn254_push_field_p(t, "_cc_py")
    t.raw_block(["_cc_y", "_cc_py"], "_cc_yok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))

    def _and_verify(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_BOOLAND"))
        e(_make_stack_op(op="opcode", code="OP_VERIFY"))

    t.raw_block(["_cc_xok", "_cc_yok"], "", _and_verify)


def emit_bn254_g1_add(emit: Callable[["StackOp"], None]) -> None:
    """Add two BN254 G1 points.

    Stack in:  [point_a, point_b] (b on top)
    Stack out: [result_point]
    """
    t = BN254Tracker(["_pa", "_pb"], emit)
    t.push_prime_cache()
    _bn254_decompose_point(t, "_pa", "px", "py")
    _bn254_decompose_point(t, "_pb", "qx", "qy")
    # R-141: both points must be canonical before anything consumes them.
    _bn254_emit_coord_canon_verify(t, "px", "py")
    _bn254_emit_coord_canon_verify(t, "qx", "qy")
    # The flag must be computed BEFORE the add: _bn254_g1_affine_add consumes
    # px/py/qx/qy.
    _bn254_g1_infinity_flag(t)
    _bn254_g1_affine_add(t)
    _bn254_g1_mask_infinity(t)
    _bn254_compose_point(t, "rx", "ry", "_result")
    t.pop_prime_cache()


def _bn254_emit_scalar_reduce(t: BN254Tracker, k_name: str, result_name: str) -> None:
    """Reduce a scalar to [0, r-1]: ((k mod r) + r) mod r.

    OP_MOD takes the sign of the DIVIDEND, so `k mod r` alone lands in
    (-r, r); the `+ r, mod r` normalises the negative half. One push of r
    covers both reductions -- the same shape as _emit_scalar_reduce in ec.py,
    whose numbers do NOT carry here (see emit_bn254_g1_scalar_mul for the
    BN254 interval bounds).

    Without it the ladder below is correct only while
    2^255 <= k + 3r < 2^256. A scalar >= 2^256 - 3r (about 2.2902*r) sets bit
    256, which the loop never reads, and one <= 2^255 - 3r drops k' under
    2^255, invalidating the accumulator seed; either way the ladder returns a
    DIFFERENT multiple of P rather than failing. In Groth16 the scalars are
    the caller-supplied PUBLIC INPUTS of vk_x = IC[0] + sum(IC[i] * pub_i),
    so the domain is attacker-chosen.
    """
    t.push_big_int("_r_red", BN254_R)

    def _red(e_):
        e_(_make_stack_op(op="opcode", code="OP_2DUP"))
        e_(_make_stack_op(op="opcode", code="OP_MOD"))
        e_(_make_stack_op(op="rot"))
        e_(_make_stack_op(op="drop"))
        e_(_make_stack_op(op="over"))
        e_(_make_stack_op(op="opcode", code="OP_ADD"))
        e_(_make_stack_op(op="swap"))
        e_(_make_stack_op(op="opcode", code="OP_MOD"))

    t.raw_block([k_name, "_r_red"], result_name, _red)


def emit_bn254_g1_scalar_mul(emit: Callable[["StackOp"], None]) -> None:
    """Perform scalar multiplication P * k on BN254 G1.

    Stack in:  [point, scalar] (scalar on top)
    Stack out: [result_point]

    Uses 254-bit double-and-add with Jacobian coordinates.
    k' = k + 3*r guarantees bit 255 is set (r is the curve order).
    """
    t = BN254Tracker(["_pt", "_k"], emit)
    t.push_prime_cache()
    # Decompose to affine base point
    _bn254_decompose_point(t, "_pt", "ax", "ay")
    # R-141: the ladder's base point must be canonical.
    _bn254_emit_coord_canon_verify(t, "ax", "ay")

    # Reduce first: the +3r trick below is only sound for k in [0, r-1], and
    # the scalar is caller input.
    t.to_top("_k")
    _bn254_emit_scalar_reduce(t, "_k", "_kr")
    t.rename("_k")

    # k' = k + 3r: guarantees bit 255 is set.
    # k in [0, r-1], so k+3r in [3r, 4r-1]. Since 3r >= 2^255, bit 255
    # is always 1. Adding 3r (= 0 mod r) preserves the EC point: k*G = (k+3r)*G.
    t.to_top("_k")
    t.push_big_int("_r1", BN254_R)
    t.raw_block(["_k", "_r1"], "_kr1",
                lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_r2", BN254_R)
    t.raw_block(["_kr1", "_r2"], "_kr2",
                lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_r3", BN254_R)
    t.raw_block(["_kr2", "_r3"], "_kr3",
                lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.rename("_k")

    # Init accumulator = P (bit 255 of k+3r is always 1)
    t.copy_to_top("ax", "jx")
    t.copy_to_top("ay", "jy")
    t.push_int("jz", 1)

    # 255 iterations: bits 254 down to 0
    for bit in range(254, -1, -1):
        # Double accumulator
        _bn254_g1_jacobian_double(t)

        # Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
        t.copy_to_top("_k", "_k_copy")
        if bit == 1:
            # Single-bit shift: OP_2DIV (no push needed)
            t.raw_block(["_k_copy"], "_shifted",
                        lambda e: e(_make_stack_op(op="opcode", code="OP_2DIV")))
        elif bit > 1:
            # Multi-bit shift: push shift amount, OP_RSHIFTNUM
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted",
                        lambda e: e(_make_stack_op(op="opcode", code="OP_RSHIFTNUM")))
        else:
            t.rename("_shifted")
        t.push_int("_two", 2)
        t.raw_block(["_shifted", "_two"], "_bit",
                    lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))

        # Move _bit to TOS and remove from tracker BEFORE generating add ops,
        # because OP_IF consumes _bit and the add ops run with _bit already gone.
        t.to_top("_bit")
        t.nm.pop()  # _bit consumed by IF
        add_ops: list = []
        add_emit = lambda op: add_ops.append(op)
        # Only the LAST step can be handed accumulator == -base (k = 0 mod r);
        # see _bn254_build_jacobian_add_affine_inline for why the strict
        # H == 0 AND R == 0 test is paid there and nowhere else.
        _bn254_build_jacobian_add_affine_inline(add_emit, t, bit == 0)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

    # Convert Jacobian to affine
    _bn254_g1_jacobian_to_affine(t, "_rx", "_ry")

    # Clean up base point and scalar
    t.to_top("ax")
    t.drop()
    t.to_top("ay")
    t.drop()
    t.to_top("_k")
    t.drop()

    # Compose result
    _bn254_compose_point(t, "_rx", "_ry", "_result")
    t.pop_prime_cache()


def emit_bn254_g1_negate(emit: Callable[["StackOp"], None]) -> None:
    """Negate a BN254 G1 point (x, p - y).

    Stack in:  [point]
    Stack out: [negated_point]
    """
    t = BN254Tracker(["_pt"], emit)
    t.push_prime_cache()
    _bn254_g1_negate(t, "_pt", "_result")
    t.pop_prime_cache()


def emit_bn254_g1_on_curve(emit: Callable[["StackOp"], None]) -> None:
    """Check if point is on BN254 G1 (y^2 = x^3 + 3 mod p).

    Stack in:  [point]
    Stack out: [boolean]
    """
    t = BN254Tracker(["_pt"], emit)
    t.push_prime_cache()

    # R-141: width. bn254G1OnCurve(G || 0xff) returned TRUE -- the OP_SPLIT at
    # 32 inside the decomposer discarded the surplus byte. Clamp and remember
    # the width rather than abort, because this predicate must stay TOTAL.
    _bn254_emit_point_length_gate(t, "_pt", 64, "_len_ok")

    _bn254_decompose_point(t, "_pt", "_x", "_y")

    # R-141: coordinate canonicity. Reject x >= p or y >= p and AND the result
    # in at the end, so the predicate still returns a boolean.
    t.copy_to_top("_x", "_x_lt")
    _bn254_push_field_p(t, "_p_for_x")
    t.raw_block(["_x_lt", "_p_for_x"], "_x_canon",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.copy_to_top("_y", "_y_lt")
    _bn254_push_field_p(t, "_p_for_y")
    t.raw_block(["_y_lt", "_p_for_y"], "_y_canon",
                lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.to_top("_x_canon")
    t.to_top("_y_canon")
    t.raw_block(["_x_canon", "_y_canon"], "_canon",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # lhs = y^2
    _bn254_field_sqr(t, "_y", "_y2")

    # rhs = x^3 + 3
    t.copy_to_top("_x", "_x_copy")
    _bn254_field_sqr(t, "_x", "_x2")
    _bn254_field_mul(t, "_x2", "_x_copy", "_x3")
    t.push_int("_three", 3)  # b = 3 for BN254
    _bn254_field_add(t, "_x3", "_three", "_rhs")

    # Compare
    t.to_top("_y2")
    t.to_top("_rhs")
    t.raw_block(["_y2", "_rhs"], "_curve_eq",
                lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))

    # on-curve = right width AND canonical AND curve-equation
    t.to_top("_canon")
    t.to_top("_curve_eq")
    t.raw_block(["_canon", "_curve_eq"], "_eq_ok",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.to_top("_len_ok")
    t.to_top("_eq_ok")
    t.raw_block(["_len_ok", "_eq_ok"], "_result",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.pop_prime_cache()


# ===========================================================================
# Dispatch table (called from stack.py)
# ===========================================================================

BN254_BUILTIN_NAMES: frozenset[str] = frozenset({
    "bn254FieldAdd", "bn254FieldSub", "bn254FieldMul",
    "bn254FieldInv", "bn254FieldNeg",
    "bn254G1Add", "bn254G1ScalarMul",
    "bn254G1Negate", "bn254G1OnCurve",
})


def is_bn254_builtin(name: str) -> bool:
    """Return True if *name* is a recognized BN254 builtin function."""
    return name in BN254_BUILTIN_NAMES


_BN254_DISPATCH: dict[str, Callable] = {
    "bn254FieldAdd": emit_bn254_field_add,
    "bn254FieldSub": emit_bn254_field_sub,
    "bn254FieldMul": emit_bn254_field_mul,
    "bn254FieldInv": emit_bn254_field_inv,
    "bn254FieldNeg": emit_bn254_field_neg,
    "bn254G1Add": emit_bn254_g1_add,
    "bn254G1ScalarMul": emit_bn254_g1_scalar_mul,
    "bn254G1Negate": emit_bn254_g1_negate,
    "bn254G1OnCurve": emit_bn254_g1_on_curve,
}


def dispatch_bn254_builtin(func_name: str, emit: Callable) -> None:
    """Call the appropriate BN254 emit function for *func_name*.

    Raises ``RuntimeError`` if *func_name* is not a known BN254 builtin.
    """
    fn = _BN254_DISPATCH.get(func_name)
    if fn is None:
        raise RuntimeError(f"unknown BN254 builtin: {func_name}")
    fn(emit)
