"""EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.

Follows the slh_dsa.py pattern: self-contained module imported by stack.py.
Uses an ECTracker (similar to SLHTracker) for named stack state tracking.

Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
Internal arithmetic uses Jacobian coordinates for scalar multiplication.

Direct port of ``compilers/go/codegen/ec.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue

# ===========================================================================
# Constants
# ===========================================================================

# secp256k1 field prime p = 2^256 - 2^32 - 977
EC_FIELD_P: int = int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)

# p - 2, used for Fermat's little theorem modular inverse
EC_FIELD_P_MINUS_2: int = EC_FIELD_P - 2

# secp256k1 generator x-coordinate
EC_GEN_X: int = int("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)

# secp256k1 generator y-coordinate
EC_GEN_Y: int = int("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)


def _bigint_to_bytes32(n: int) -> bytes:
    """Convert an int to a 32-byte big-endian byte string."""
    return n.to_bytes(32, byteorder="big")


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    # Map convenience kwarg names to StackOp field names
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _make_push_value(*, kind: str, **kwargs) -> "PushValue":
    from runar_compiler.codegen.stack import PushValue
    # Map convenience kwarg names to PushValue field names
    if "bytes_" in kwargs:
        kwargs["bytes_val"] = kwargs.pop("bytes_")
    return PushValue(kind=kind, **kwargs)


def _big_int_push(n: int) -> "PushValue":
    from runar_compiler.codegen.stack import big_int_push
    return big_int_push(n)


# ===========================================================================
# ECTracker -- named stack state tracker (mirrors TS ECTracker)
# ===========================================================================

class ECTracker:
    """Tracks named stack positions and emits StackOps for EC codegen."""

    def __init__(self, init: list[str], emit: Callable[["StackOp"], None]) -> None:
        self.nm: list[str] = list(init)
        self.e = emit

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"ECTracker: '{name}' not on stack {self.nm}")

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
        for _ in reversed(consume):
            if self.nm:
                self.nm.pop()
        fn(self.e)
        if produce:
            self.nm.append(produce)

    def emit_if(
        self,
        cond_name: str,
        then_fn: Callable[[Callable[["StackOp"], None]], None],
        else_fn: Callable[[Callable[["StackOp"], None]], None],
        result_name: str,
    ) -> None:
        """Emit if/else with tracked stack effect.

        *result_name* = "" means no result pushed.
        """
        self.to_top(cond_name)
        # condition consumed
        if self.nm:
            self.nm.pop()
        then_ops: list["StackOp"] = []
        else_ops: list["StackOp"] = []
        then_fn(lambda op: then_ops.append(op))
        else_fn(lambda op: else_ops.append(op))
        self.e(_make_stack_op(op="if", then=then_ops, else_=else_ops))
        if result_name:
            self.nm.append(result_name)


# ===========================================================================
# Field arithmetic helpers
# ===========================================================================

def _ec_push_field_p(t: ECTracker, name: str) -> None:
    """Push the field prime p onto the stack as a script number."""
    t.push_big_int(name, EC_FIELD_P)


def _ec_field_mod(t: ECTracker, a_name: str, result_name: str) -> None:
    """Reduce TOS mod p, ensuring non-negative result."""
    t.to_top(a_name)
    _ec_push_field_p(t, "_fmod_p")
    # (a % p + p) % p
    def _fn(e: Callable) -> None:
        e(_make_stack_op(op="opcode", code="OP_2DUP"))   # a p a p
        e(_make_stack_op(op="opcode", code="OP_MOD"))     # a p (a%p)
        e(_make_stack_op(op="rot"))                        # p (a%p) a
        e(_make_stack_op(op="drop"))                       # p (a%p)
        e(_make_stack_op(op="over"))                       # p (a%p) p
        e(_make_stack_op(op="opcode", code="OP_ADD"))      # p (a%p+p)
        e(_make_stack_op(op="swap"))                       # (a%p+p) p
        e(_make_stack_op(op="opcode", code="OP_MOD"))      # ((a%p+p)%p)
    t.raw_block([a_name, "_fmod_p"], result_name, _fn)


def _ec_field_add(t: ECTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a + b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fadd_sum", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    _ec_field_mod(t, "_fadd_sum", result_name)


def _ec_field_sub(t: ECTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a - b) mod p (non-negative)."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fsub_diff", lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))
    _ec_field_mod(t, "_fsub_diff", result_name)


def _ec_field_mul(t: ECTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a * b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fmul_prod", lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    _ec_field_mod(t, "_fmul_prod", result_name)


def _ec_field_sqr(t: ECTracker, a_name: str, result_name: str) -> None:
    """Compute (a * a) mod p."""
    t.copy_to_top(a_name, "_fsqr_copy")
    _ec_field_mul(t, a_name, "_fsqr_copy", result_name)


def _ec_field_inv(t: ECTracker, a_name: str, result_name: str) -> None:
    """Compute a^(p-2) mod p via square-and-multiply.

    Consumes *a_name* from the tracker.
    """
    # p-2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
    # Bits 255..32: 224 bits, all 1 except bit 32 which is 0
    # Bits 31..0: 0xFFFFFC2D

    # Start: result = a (bit 255 = 1)
    t.copy_to_top(a_name, "_inv_r")
    # Bits 254 down to 33: all 1's (222 bits). Bit 32 is 0 (handled below).
    for _ in range(222):
        _ec_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")
        t.copy_to_top(a_name, "_inv_a")
        _ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
        t.rename("_inv_r")
    # Bit 32 is 0: square only (no multiply)
    _ec_field_sqr(t, "_inv_r", "_inv_r2")
    t.rename("_inv_r")
    # Bits 31 down to 0 of p-2
    low_bits = EC_FIELD_P_MINUS_2 & 0xFFFFFFFF
    for i in range(31, -1, -1):
        _ec_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")
        if (low_bits >> i) & 1 == 1:
            t.copy_to_top(a_name, "_inv_a")
            _ec_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")
    # Clean up original input and rename result
    t.to_top(a_name)
    t.drop()
    t.to_top("_inv_r")
    t.rename(result_name)


# ===========================================================================
# Point decompose / compose
# ===========================================================================

def _ec_emit_reverse32(e: Callable) -> None:
    """Emit inline byte reversal for a 32-byte value on TOS."""
    # Push empty accumulator, swap with data
    e(_make_stack_op(op="opcode", code="OP_0"))
    e(_make_stack_op(op="swap"))
    # 32 iterations: peel first byte, prepend to accumulator
    for _ in range(32):
        # Stack: [accum, remaining]
        e(_make_stack_op(op="push", value=_big_int_push(1)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        # Stack: [accum, byte0, rest]
        e(_make_stack_op(op="rot"))
        # Stack: [byte0, rest, accum]
        e(_make_stack_op(op="rot"))
        # Stack: [rest, accum, byte0]
        e(_make_stack_op(op="swap"))
        # Stack: [rest, byte0, accum]
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        # Stack: [rest, byte0||accum]
        e(_make_stack_op(op="swap"))
        # Stack: [byte0||accum, rest]
    # Stack: [reversed, empty]
    e(_make_stack_op(op="drop"))


def _ec_decompose_point(t: ECTracker, point_name: str, x_name: str, y_name: str) -> None:
    """Decompose a 64-byte Point into (x_num, y_num) on stack.

    Consumes *point_name*, produces *x_name* and *y_name*.
    """
    t.to_top(point_name)
    # OP_SPLIT at 32 produces x_bytes (bottom) and y_bytes (top)
    def _split(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
    t.raw_block([point_name], "", _split)
    # Manually track the two new items
    t.nm.append("_dp_xb")
    t.nm.append("_dp_yb")

    # Convert y_bytes (on top) to num
    # Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
    def _convert_y(e: Callable) -> None:
        _ec_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_yb"], y_name, _convert_y)

    # Convert x_bytes to num
    t.to_top("_dp_xb")
    def _convert_x(e: Callable) -> None:
        _ec_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_xb"], x_name, _convert_x)

    # Stack: [yName, xName] -- swap to standard order [xName, yName]
    t.swap()


def _ec_compose_point(t: ECTracker, x_name: str, y_name: str, result_name: str) -> None:
    """Compose (x_num, y_num) into a 64-byte Point.

    Consumes *x_name* and *y_name*, produces *result_name*.
    """
    # Convert x to 32-byte big-endian
    t.to_top(x_name)
    def _convert_x(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(33)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        # Drop the sign byte (last byte) -- split at 32, keep left
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        _ec_emit_reverse32(e)
    t.raw_block([x_name], "_cp_xb", _convert_x)

    # Convert y to 32-byte big-endian
    t.to_top(y_name)
    def _convert_y(e: Callable) -> None:
        e(_make_stack_op(op="push", value=_big_int_push(33)))
        e(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
        e(_make_stack_op(op="push", value=_big_int_push(32)))
        e(_make_stack_op(op="opcode", code="OP_SPLIT"))
        e(_make_stack_op(op="drop"))
        _ec_emit_reverse32(e)
    t.raw_block([y_name], "_cp_yb", _convert_y)

    # Cat: x_be || y_be (x is below y after the two to_top calls)
    t.to_top("_cp_xb")
    t.to_top("_cp_yb")
    t.raw_block(["_cp_xb", "_cp_yb"], result_name, lambda e: e(_make_stack_op(op="opcode", code="OP_CAT")))


# ===========================================================================
# Affine point addition (for ecAdd)
# ===========================================================================

def _ec_affine_add(t: ECTracker) -> None:
    """Perform affine point addition.

    Expects px, py, qx, qy on tracker. Produces rx, ry. Consumes all four inputs.
    """
    # s_num = qy - py
    t.copy_to_top("qy", "_qy1")
    t.copy_to_top("py", "_py1")
    _ec_field_sub(t, "_qy1", "_py1", "_s_num")

    # s_den = qx - px
    t.copy_to_top("qx", "_qx1")
    t.copy_to_top("px", "_px1")
    _ec_field_sub(t, "_qx1", "_px1", "_s_den")

    # s = s_num / s_den mod p
    _ec_field_inv(t, "_s_den", "_s_den_inv")
    _ec_field_mul(t, "_s_num", "_s_den_inv", "_s")

    # rx = s^2 - px - qx mod p
    t.copy_to_top("_s", "_s_keep")
    _ec_field_sqr(t, "_s", "_s2")
    t.copy_to_top("px", "_px2")
    _ec_field_sub(t, "_s2", "_px2", "_rx1")
    t.copy_to_top("qx", "_qx2")
    _ec_field_sub(t, "_rx1", "_qx2", "rx")

    # ry = s * (px - rx) - py mod p
    t.copy_to_top("px", "_px3")
    t.copy_to_top("rx", "_rx2")
    _ec_field_sub(t, "_px3", "_rx2", "_px_rx")
    _ec_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
    t.copy_to_top("py", "_py2")
    _ec_field_sub(t, "_s_px_rx", "_py2", "ry")

    # Clean up original points
    t.to_top("px")
    t.drop()
    t.to_top("py")
    t.drop()
    t.to_top("qx")
    t.drop()
    t.to_top("qy")
    t.drop()


def _ec_affine_double(t: ECTracker) -> None:
    """Affine point doubling: 2*P for P=(px, py).

    Expects px, py on tracker. Consumes both, produces rx, ry.

    Formula (secp256k1, a=0):
      s = 3*px^2 / (2*py) mod p
      rx = s^2 - 2*px mod p
      ry = s*(px - rx) - py mod p
    """
    # s_num = 3 * px^2
    t.copy_to_top("px", "_px_copy")
    _ec_field_sqr(t, "_px_copy", "_px2")
    t.push_int("_three_d", 3)
    _ec_field_mul(t, "_px2", "_three_d", "_s_num")

    # s_den = 2 * py
    t.copy_to_top("py", "_py_copy")
    t.push_int("_two_d", 2)
    _ec_field_mul(t, "_py_copy", "_two_d", "_s_den")

    # s = s_num / s_den mod p
    _ec_field_inv(t, "_s_den", "_s_den_inv")
    _ec_field_mul(t, "_s_num", "_s_den_inv", "_s")

    # rx = s^2 - 2*px mod p
    t.copy_to_top("_s", "_s_keep")
    _ec_field_sqr(t, "_s", "_s2")
    t.copy_to_top("px", "_px2b")
    t.push_int("_two_d2", 2)
    _ec_field_mul(t, "_px2b", "_two_d2", "_2px")
    _ec_field_sub(t, "_s2", "_2px", "rx")

    # ry = s*(px - rx) - py mod p
    t.copy_to_top("px", "_px3")
    t.copy_to_top("rx", "_rx2")
    _ec_field_sub(t, "_px3", "_rx2", "_px_rx")
    _ec_field_mul(t, "_s_keep", "_px_rx", "_s_px_rx")
    t.copy_to_top("py", "_py2d")
    _ec_field_sub(t, "_s_px_rx", "_py2d", "ry")

    # Clean up original point
    t.to_top("px")
    t.drop()
    t.to_top("py")
    t.drop()


# ===========================================================================
# Jacobian point operations (for ecMul)
# ===========================================================================

def _ec_jacobian_double(t: ECTracker) -> None:
    """Perform Jacobian point doubling (a=0 for secp256k1).

    Expects jx, jy, jz on tracker. Replaces with updated values.
    """
    # Save copies of jx, jy, jz for later use
    t.copy_to_top("jy", "_jy_save")
    t.copy_to_top("jx", "_jx_save")
    t.copy_to_top("jz", "_jz_save")

    # A = jy^2
    _ec_field_sqr(t, "jy", "_A")

    # B = 4 * jx * A
    t.copy_to_top("_A", "_A_save")
    _ec_field_mul(t, "jx", "_A", "_xA")
    t.push_int("_four", 4)
    _ec_field_mul(t, "_xA", "_four", "_B")

    # C = 8 * A^2
    _ec_field_sqr(t, "_A_save", "_A2")
    t.push_int("_eight", 8)
    _ec_field_mul(t, "_A2", "_eight", "_C")

    # D = 3 * X^2
    _ec_field_sqr(t, "_jx_save", "_x2")
    t.push_int("_three", 3)
    _ec_field_mul(t, "_x2", "_three", "_D")

    # nx = D^2 - 2*B
    t.copy_to_top("_D", "_D_save")
    t.copy_to_top("_B", "_B_save")
    _ec_field_sqr(t, "_D", "_D2")
    t.copy_to_top("_B", "_B1")
    t.push_int("_two1", 2)
    _ec_field_mul(t, "_B1", "_two1", "_2B")
    _ec_field_sub(t, "_D2", "_2B", "_nx")

    # ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy")
    _ec_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
    _ec_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
    _ec_field_sub(t, "_D_B_nx", "_C", "_ny")

    # nz = 2 * Y * Z
    _ec_field_mul(t, "_jy_save", "_jz_save", "_yz")
    t.push_int("_two2", 2)
    _ec_field_mul(t, "_yz", "_two2", "_nz")

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


def _ec_jacobian_to_affine(t: ECTracker, rx_name: str, ry_name: str) -> None:
    """Convert Jacobian to affine coordinates.

    Consumes jx, jy, jz; produces *rx_name*, *ry_name*.
    """
    _ec_field_inv(t, "jz", "_zinv")
    t.copy_to_top("_zinv", "_zinv_keep")
    _ec_field_sqr(t, "_zinv", "_zinv2")
    t.copy_to_top("_zinv2", "_zinv2_keep")
    _ec_field_mul(t, "_zinv_keep", "_zinv2", "_zinv3")
    _ec_field_mul(t, "jx", "_zinv2_keep", rx_name)
    _ec_field_mul(t, "jy", "_zinv3", ry_name)


# ===========================================================================
# Jacobian mixed addition (P_jacobian + Q_affine)
# ===========================================================================

def _ec_build_jacobian_add_affine_inline(e: Callable, t: ECTracker) -> None:
    """Build Jacobian mixed-add ops for use inside OP_IF.

    Uses an inner ECTracker to leverage field arithmetic helpers.

    Stack layout: [..., ax, ay, _k, jx, jy, jz]
    After:        [..., ax, ay, _k, jx', jy', jz']
    """
    # Create inner tracker with cloned stack state
    it = ECTracker(list(t.nm), e)

    # Save copies of values that get consumed but are needed later
    it.copy_to_top("jz", "_jz_for_z1cu")   # consumed by Z1sq, needed for Z1cu
    it.copy_to_top("jz", "_jz_for_z3")     # needed for Z3
    it.copy_to_top("jy", "_jy_for_y3")     # consumed by R, needed for Y3
    it.copy_to_top("jx", "_jx_for_u1h2")   # consumed by H, needed for U1H2

    # Z1sq = jz^2
    _ec_field_sqr(it, "jz", "_Z1sq")

    # Z1cu = _jz_for_z1cu * Z1sq (copy Z1sq for U2)
    it.copy_to_top("_Z1sq", "_Z1sq_for_u2")
    _ec_field_mul(it, "_jz_for_z1cu", "_Z1sq", "_Z1cu")

    # U2 = ax * Z1sq_for_u2
    it.copy_to_top("ax", "_ax_c")
    _ec_field_mul(it, "_ax_c", "_Z1sq_for_u2", "_U2")

    # S2 = ay * Z1cu
    it.copy_to_top("ay", "_ay_c")
    _ec_field_mul(it, "_ay_c", "_Z1cu", "_S2")

    # H = U2 - jx
    _ec_field_sub(it, "_U2", "jx", "_H")

    # R = S2 - jy
    _ec_field_sub(it, "_S2", "jy", "_R")

    # Save copies of H (consumed by H2 sqr, needed for H3 and Z3)
    it.copy_to_top("_H", "_H_for_h3")
    it.copy_to_top("_H", "_H_for_z3")

    # H2 = H^2
    _ec_field_sqr(it, "_H", "_H2")

    # Save H2 for U1H2
    it.copy_to_top("_H2", "_H2_for_u1h2")

    # H3 = H_for_h3 * H2
    _ec_field_mul(it, "_H_for_h3", "_H2", "_H3")

    # U1H2 = _jx_for_u1h2 * H2_for_u1h2
    _ec_field_mul(it, "_jx_for_u1h2", "_H2_for_u1h2", "_U1H2")

    # Save R, U1H2, H3 for Y3 computation
    it.copy_to_top("_R", "_R_for_y3")
    it.copy_to_top("_U1H2", "_U1H2_for_y3")
    it.copy_to_top("_H3", "_H3_for_y3")

    # X3 = R^2 - H3 - 2*U1H2
    _ec_field_sqr(it, "_R", "_R2")
    _ec_field_sub(it, "_R2", "_H3", "_x3_tmp")
    it.push_int("_two", 2)
    _ec_field_mul(it, "_U1H2", "_two", "_2U1H2")
    _ec_field_sub(it, "_x3_tmp", "_2U1H2", "_X3")

    # Y3 = R_for_y3*(U1H2_for_y3 - X3) - jy_for_y3*H3_for_y3
    it.copy_to_top("_X3", "_X3_c")
    _ec_field_sub(it, "_U1H2_for_y3", "_X3_c", "_u_minus_x")
    _ec_field_mul(it, "_R_for_y3", "_u_minus_x", "_r_tmp")
    _ec_field_mul(it, "_jy_for_y3", "_H3_for_y3", "_jy_h3")
    _ec_field_sub(it, "_r_tmp", "_jy_h3", "_Y3")

    # Z3 = _jz_for_z3 * _H_for_z3
    _ec_field_mul(it, "_jz_for_z3", "_H_for_z3", "_Z3")

    # Rename results to jx/jy/jz
    it.to_top("_X3")
    it.rename("jx")
    it.to_top("_Y3")
    it.rename("jy")
    it.to_top("_Z3")
    it.rename("jz")


# ===========================================================================
# Public entry points (called from stack lowerer)
# ===========================================================================

def emit_ec_add(emit: Callable) -> None:
    """Add two points.

    Stack in: [point_a, point_b] (b on top)
    Stack out: [result_point]
    """
    t = ECTracker(["_pa", "_pb"], emit)
    _ec_decompose_point(t, "_pa", "px", "py")
    _ec_decompose_point(t, "_pb", "qx", "qy")
    _ec_affine_add(t)
    _ec_compose_point(t, "rx", "ry", "_result")


def emit_ec_mul(emit: Callable) -> None:
    """Perform scalar multiplication P * k.

    Stack in: [point, scalar] (scalar on top)
    Stack out: [result_point]

    Uses 256-iteration double-and-add with Jacobian coordinates.
    """
    t = ECTracker(["_pt", "_k"], emit)
    # Decompose to affine base point
    _ec_decompose_point(t, "_pt", "ax", "ay")

    # k' = k + 3n: guarantees bit 257 is set.
    # k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
    # is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
    curve_n = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
    t.to_top("_k")
    t.push_big_int("_n", curve_n)
    t.raw_block(["_k", "_n"], "_kn", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_n2", curve_n)
    t.raw_block(["_kn", "_n2"], "_kn2", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_big_int("_n3", curve_n)
    t.raw_block(["_kn2", "_n3"], "_kn3", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.rename("_k")

    # Pre-compute 2*P via affine doubling and store on altstack.
    # This handles the degenerate case where the mixed Jacobian-affine addition
    # hits P+P (H=0 -> Z3=0), which happens for ecMul(P, 2).
    # Computing OUTSIDE the IF/ELSE avoids issues with field ops inside ELSE branches.
    # Stack: [ax, ay, _k]
    t.copy_to_top("ax", "px")
    t.copy_to_top("ay", "py")
    _ec_affine_double(t)
    # Stack: [ax, ay, _k, rx, ry] -- ry on top
    # Push ry first, then rx to altstack so LIFO pop gives rx then ry
    t.to_alt()  # ry -> altstack
    t.to_alt()  # rx -> altstack
    # Stack: [ax, ay, _k], Altstack: [ry_2p, rx_2p] (top = rx_2p)

    # Init accumulator = P (bit 257 of k+3n is always 1)
    t.copy_to_top("ax", "jx")
    t.copy_to_top("ay", "jy")
    t.push_int("jz", 1)

    # 257 iterations: bits 256 down to 0
    for bit in range(256, -1, -1):
        # Double accumulator
        _ec_jacobian_double(t)

        # Extract bit: (k >> bit) & 1, using OP_DIV for right-shift
        t.copy_to_top("_k", "_k_copy")
        if bit > 0:
            divisor = 1 << bit
            t.push_big_int("_div", divisor)
            t.raw_block(["_k_copy", "_div"], "_shifted", lambda e: e(_make_stack_op(op="opcode", code="OP_DIV")))
        else:
            t.rename("_shifted")
        t.push_int("_two", 2)
        t.raw_block(["_shifted", "_two"], "_bit", lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))

        # Move _bit to TOS and remove from tracker BEFORE generating add ops,
        # because OP_IF consumes _bit and the add ops run with _bit already gone.
        t.to_top("_bit")
        t.nm.pop()  # _bit consumed by IF
        add_ops: list = []
        add_emit = lambda op: add_ops.append(op)
        _ec_build_jacobian_add_affine_inline(add_emit, t)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

    # Check for degenerate case: Z=0 means the mixed addition hit P+P.
    # Stack: [ax, ay, _k, jx, jy, jz], Altstack: [ry_2p, rx_2p] (top = rx_2p)
    t.copy_to_top("jz", "_z_chk")
    t.to_top("_z_chk")
    t.nm.pop()  # consumed by IF

    # Normal path (Z!=0): Jacobian to affine, discard altstack 2P values
    normal_ops: list = []
    def _build_normal(ne):
        nt = ECTracker(list(t.nm), ne)
        _ec_jacobian_to_affine(nt, "_rx", "_ry")
        # Discard pre-computed 2P from altstack (LIFO: rx_2p first, then ry_2p)
        nt.from_alt("_alt_rx_d")
        nt.to_top("_alt_rx_d")
        nt.drop()
        nt.from_alt("_alt_ry_d")
        nt.to_top("_alt_ry_d")
        nt.drop()
    _build_normal(lambda op: normal_ops.append(op))

    # Degenerate path (Z=0): drop jx,jy,jz, retrieve 2P from altstack
    deg_ops: list = []
    def _build_deg(de):
        dt = ECTracker(list(t.nm), de)
        dt.to_top("jz")
        dt.drop()
        dt.to_top("jy")
        dt.drop()
        dt.to_top("jx")
        dt.drop()
        # Retrieve pre-computed 2P from altstack (LIFO: rx_2p first, then ry_2p)
        dt.from_alt("_rx")
        dt.from_alt("_ry")
    _build_deg(lambda op: deg_ops.append(op))

    emit(_make_stack_op(op="if", then=normal_ops, else_=deg_ops))
    # Both branches leave: [ax, ay, _k, _rx, _ry]
    t.nm.pop()  # remove jz (consumed/dropped)
    t.nm.pop()  # remove jy (consumed/dropped)
    t.nm.pop()  # remove jx (consumed/dropped)
    t.nm.append("_rx")
    t.nm.append("_ry")

    # Clean up base point and scalar
    t.to_top("ax")
    t.drop()
    t.to_top("ay")
    t.drop()
    t.to_top("_k")
    t.drop()

    # Compose result
    _ec_compose_point(t, "_rx", "_ry", "_result")


def emit_ec_mul_gen(emit: Callable) -> None:
    """Perform scalar multiplication G * k.

    Stack in: [scalar]
    Stack out: [result_point]
    """
    # Push generator point as 64-byte blob, then delegate to ecMul
    g_point = _bigint_to_bytes32(EC_GEN_X) + _bigint_to_bytes32(EC_GEN_Y)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_ec_mul(emit)


def emit_ec_negate(emit: Callable) -> None:
    """Negate a point (x, p - y).

    Stack in: [point]
    Stack out: [negated_point]
    """
    t = ECTracker(["_pt"], emit)
    _ec_decompose_point(t, "_pt", "_nx", "_ny")
    _ec_push_field_p(t, "_fp")
    _ec_field_sub(t, "_fp", "_ny", "_neg_y")
    _ec_compose_point(t, "_nx", "_neg_y", "_result")


def emit_ec_on_curve(emit: Callable) -> None:
    """Check if point is on secp256k1 (y^2 = x^3 + 7 mod p).

    Stack in: [point]
    Stack out: [boolean]
    """
    t = ECTracker(["_pt"], emit)
    _ec_decompose_point(t, "_pt", "_x", "_y")

    # lhs = y^2
    _ec_field_sqr(t, "_y", "_y2")

    # rhs = x^3 + 7
    t.copy_to_top("_x", "_x_copy")
    _ec_field_sqr(t, "_x", "_x2")
    _ec_field_mul(t, "_x2", "_x_copy", "_x3")
    t.push_int("_seven", 7)
    _ec_field_add(t, "_x3", "_seven", "_rhs")

    # Compare
    t.to_top("_y2")
    t.to_top("_rhs")
    t.raw_block(["_y2", "_rhs"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))


def emit_ec_mod_reduce(emit: Callable) -> None:
    """Compute ((value % mod) + mod) % mod.

    Stack in: [value, mod]
    Stack out: [result]
    """
    emit(_make_stack_op(op="opcode", code="OP_2DUP"))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    emit(_make_stack_op(op="rot"))
    emit(_make_stack_op(op="drop"))
    emit(_make_stack_op(op="over"))
    emit(_make_stack_op(op="opcode", code="OP_ADD"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))


def emit_ec_encode_compressed(emit: Callable) -> None:
    """Encode a point as a 33-byte compressed pubkey.

    Stack in: [point (64 bytes)]
    Stack out: [compressed (33 bytes)]
    """
    # Split at 32: [x_bytes, y_bytes]
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    # Get last byte of y for parity
    emit(_make_stack_op(op="opcode", code="OP_SIZE"))
    emit(_make_stack_op(op="push", value=_big_int_push(1)))
    emit(_make_stack_op(op="opcode", code="OP_SUB"))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    # Stack: [x_bytes, y_prefix, last_byte]
    emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    emit(_make_stack_op(op="push", value=_big_int_push(2)))
    emit(_make_stack_op(op="opcode", code="OP_MOD"))
    # Stack: [x_bytes, y_prefix, parity]
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))  # drop y_prefix
    # Stack: [x_bytes, parity]
    emit(_make_stack_op(
        op="if",
        then=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x03"))],
        else_=[_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x02"))],
    ))
    # Stack: [x_bytes, prefix_byte]
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


def emit_ec_make_point(emit: Callable) -> None:
    """Convert (x: bigint, y: bigint) to a 64-byte Point.

    Stack in: [x_num, y_num] (y on top)
    Stack out: [point_bytes (64 bytes)]
    """
    # Convert y to 32 bytes big-endian
    emit(_make_stack_op(op="push", value=_big_int_push(33)))
    emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="drop"))
    _ec_emit_reverse32(emit)
    # Stack: [x_num, y_be]
    emit(_make_stack_op(op="swap"))
    # Stack: [y_be, x_num]
    emit(_make_stack_op(op="push", value=_big_int_push(33)))
    emit(_make_stack_op(op="opcode", code="OP_NUM2BIN"))
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="drop"))
    _ec_emit_reverse32(emit)
    # Stack: [y_be, x_be]
    emit(_make_stack_op(op="swap"))
    # Stack: [x_be, y_be]
    emit(_make_stack_op(op="opcode", code="OP_CAT"))


def emit_ec_point_x(emit: Callable) -> None:
    """Extract the x-coordinate from a Point.

    Stack in: [point (64 bytes)]
    Stack out: [x as bigint]
    """
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="drop"))
    _ec_emit_reverse32(emit)
    # Append 0x00 sign byte to ensure unsigned interpretation
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))


def emit_ec_point_y(emit: Callable) -> None:
    """Extract the y-coordinate from a Point.

    Stack in: [point (64 bytes)]
    Stack out: [y as bigint]
    """
    emit(_make_stack_op(op="push", value=_big_int_push(32)))
    emit(_make_stack_op(op="opcode", code="OP_SPLIT"))
    emit(_make_stack_op(op="swap"))
    emit(_make_stack_op(op="drop"))
    _ec_emit_reverse32(emit)
    # Append 0x00 sign byte to ensure unsigned interpretation
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
    emit(_make_stack_op(op="opcode", code="OP_CAT"))
    emit(_make_stack_op(op="opcode", code="OP_BIN2NUM"))


# ===========================================================================
# Dispatch table (called from stack.py)
# ===========================================================================

EC_BUILTIN_NAMES: frozenset[str] = frozenset({
    "ecAdd", "ecMul", "ecMulGen",
    "ecNegate", "ecOnCurve", "ecModReduce",
    "ecEncodeCompressed", "ecMakePoint",
    "ecPointX", "ecPointY",
})


def is_ec_builtin(name: str) -> bool:
    """Return True if *name* is a recognized EC builtin function."""
    return name in EC_BUILTIN_NAMES


_EC_DISPATCH: dict[str, Callable] = {
    "ecAdd": emit_ec_add,
    "ecMul": emit_ec_mul,
    "ecMulGen": emit_ec_mul_gen,
    "ecNegate": emit_ec_negate,
    "ecOnCurve": emit_ec_on_curve,
    "ecModReduce": emit_ec_mod_reduce,
    "ecEncodeCompressed": emit_ec_encode_compressed,
    "ecMakePoint": emit_ec_make_point,
    "ecPointX": emit_ec_point_x,
    "ecPointY": emit_ec_point_y,
}


def dispatch_ec_builtin(func_name: str, emit: Callable) -> None:
    """Call the appropriate EC emit function for *func_name*.

    Raises ``RuntimeError`` if *func_name* is not a known EC builtin.
    """
    fn = _EC_DISPATCH.get(func_name)
    if fn is None:
        raise RuntimeError(f"unknown EC builtin: {func_name}")
    fn(emit)
