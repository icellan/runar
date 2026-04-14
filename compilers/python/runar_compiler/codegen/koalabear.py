"""KoalaBear field arithmetic codegen -- KoalaBear prime field operations for Bitcoin Script.

Follows the babybear.py pattern: self-contained module imported by stack.py.
Uses a KBTracker for named stack state tracking.

KoalaBear prime: p = 2^31 - 2^24 + 1 = 2,130,706,433 (0x7f000001)
Used by SP1 v6 STARK proofs (StackedBasefold verification).

All values fit in a single BSV script number (31-bit prime).
No multi-limb arithmetic needed.

Direct port of ``compilers/go/codegen/koalabear.go``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue

# ===========================================================================
# Constants
# ===========================================================================

# KoalaBear field prime p = 2^31 - 2^24 + 1 = 2,130,706,433
KB_P: int = 2130706433
# p - 2, used for Fermat's little theorem modular inverse
KB_P_MINUS_2: int = 2130706431
# Quartic extension non-residue W = 3 (irreducible x^4 - 3)
KB_W: int = 3


# ---------------------------------------------------------------------------
# Lazy imports to avoid circular dependency with stack.py
# ---------------------------------------------------------------------------

def _make_stack_op(*, op: str, **kwargs) -> "StackOp":
    from runar_compiler.codegen.stack import StackOp
    if "else_" in kwargs:
        kwargs["else_ops"] = kwargs.pop("else_")
    return StackOp(op=op, **kwargs)


def _big_int_push(n: int) -> "PushValue":
    from runar_compiler.codegen.stack import big_int_push
    return big_int_push(n)


# ===========================================================================
# KBTracker -- named stack state tracker (mirrors BBTracker / Go KBTracker)
# ===========================================================================

class KBTracker:
    """Tracks named stack positions and emits StackOps for KoalaBear codegen."""

    def __init__(self, init: list[str], emit: Callable[["StackOp"], None]) -> None:
        self.nm: list[str] = list(init)
        self.e = emit
        self._prime_cache_active: bool = False

    @property
    def depth(self) -> int:
        return len(self.nm)

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"KBTracker: '{name}' not on stack {self.nm}")

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

    def pick(self, n: str, d: int) -> None:
        if d == 0:
            self.dup(n)
            return
        if d == 1:
            self.over(n)
            return
        self.e(_make_stack_op(op="push", value=_big_int_push(d)))
        self.nm.append(None)
        self.e(_make_stack_op(op="pick", depth=d))
        self.nm.pop()
        self.nm.append(n)

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
        self.nm.append(None)
        self.e(_make_stack_op(op="roll", depth=d))
        self.nm.pop()
        idx = len(self.nm) - 1 - d
        item = self.nm[idx]
        del self.nm[idx]
        self.nm.append(item)

    def copy_to_top(self, name: str, new_name: str) -> None:
        """Bring a named value to stack top (non-consuming copy via PICK)."""
        d = self.find_depth(name)
        if d == 0:
            self.dup(new_name)
        else:
            self.pick(new_name, d)

    def to_top(self, name: str) -> None:
        """Bring a named value to stack top (consuming via ROLL)."""
        d = self.find_depth(name)
        if d == 0:
            return
        self.roll(d)

    def rename(self, new_name: str) -> None:
        """Rename the top-of-stack entry."""
        if self.nm:
            self.nm[-1] = new_name

    def raw_block(
        self,
        consume: list[str],
        produce: str | None,
        fn: Callable[[Callable[["StackOp"], None]], None],
    ) -> None:
        """Emit raw opcodes; tracker only records net stack effect."""
        fn(self.e)
        for _ in range(len(consume)):
            if self.nm:
                self.nm.pop()
        if produce is not None:
            self.nm.append(produce)

    # -----------------------------------------------------------------------
    # Prime cache helpers (alt-stack caching for the KoalaBear prime)
    # -----------------------------------------------------------------------

    def push_prime_cache(self) -> None:
        """Push the KoalaBear prime to the alt-stack for caching.

        All subsequent field operations will use the cached prime instead of
        pushing fresh literals, saving ~50 KB of script per permutation.
        """
        self.e(_make_stack_op(op="push", value=_big_int_push(KB_P)))
        self.e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        self._prime_cache_active = True

    def pop_prime_cache(self) -> None:
        """Remove the cached prime from the alt-stack."""
        self.e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
        self.e(_make_stack_op(op="drop"))
        self._prime_cache_active = False

    def emit_prime(self, e: Callable[["StackOp"], None]) -> None:
        """Emit the field prime onto the stack — either from cache or fresh push."""
        if self._prime_cache_active:
            e(_make_stack_op(op="opcode", code="OP_FROMALTSTACK"))
            e(_make_stack_op(op="opcode", code="OP_DUP"))
            e(_make_stack_op(op="opcode", code="OP_TOALTSTACK"))
        else:
            e(_make_stack_op(op="push", value=_big_int_push(KB_P)))


# ===========================================================================
# Field arithmetic internals
# ===========================================================================

def _kb_field_mod(t: KBTracker, a_name: str, result_name: str) -> None:
    """Reduce value mod p, ensuring non-negative result.

    Pattern: (a % p + p) % p — handles negative values from sub.
    Uses cached prime from alt-stack when available.
    """
    t.to_top(a_name)
    t.raw_block([a_name], result_name, lambda e: (
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_ADD")),
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _kb_field_add_unreduced(t: KBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute a + b WITHOUT modular reduction.

    Result is in [0, 2p-2]. Safe when the result will be immediately consumed
    by multiplication (which applies its own mod) or further additions where
    the total stays within BSV script number limits (~2^63).
    KoalaBear p ≈ 2^31, so up to ~2^32 unreduced sums are safe.
    """
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], result_name, lambda e: (
        e(_make_stack_op(op="opcode", code="OP_ADD")),
    ))


def _kb_field_add(t: KBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a + b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_kb_add", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_ADD")),
    ))
    # Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    t.to_top("_kb_add")
    t.raw_block(["_kb_add"], result_name, lambda e: (
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _kb_field_sub(t: KBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a - b) mod p (non-negative)."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_kb_diff", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_SUB")),
    ))
    # Difference can be negative, need full mod-reduce
    _kb_field_mod(t, "_kb_diff", result_name)


def _kb_field_mul(t: KBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a * b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_kb_prod", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_MUL")),
    ))
    # Product of two non-negative values is non-negative, simple OP_MOD
    t.to_top("_kb_prod")
    t.raw_block(["_kb_prod"], result_name, lambda e: (
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _kb_field_sqr(t: KBTracker, a_name: str, result_name: str) -> None:
    """Compute (a * a) mod p."""
    t.copy_to_top(a_name, "_kb_sqr_copy")
    _kb_field_mul(t, a_name, "_kb_sqr_copy", result_name)


def _kb_field_mul_const(t: KBTracker, a_name: str, c: int, result_name: str) -> None:
    """Compute (a * c) mod p where c is a constant.

    Uses OP_2MUL when c==2 and OP_LSHIFTNUM when c is a power of 2 > 2.
    """
    t.to_top(a_name)
    if c == 2:
        t.raw_block([a_name], "_kb_mc", lambda e: (
            e(_make_stack_op(op="opcode", code="OP_2MUL")),
        ))
    elif c > 2 and (c & (c - 1)) == 0:
        # c is a power of 2 > 2 — use OP_LSHIFTNUM
        shift = (c).bit_length() - 1
        t.raw_block([a_name], "_kb_mc", lambda e: (
            e(_make_stack_op(op="push", value=_big_int_push(shift))),
            e(_make_stack_op(op="opcode", code="OP_LSHIFTNUM")),
        ))
    else:
        t.raw_block([a_name], "_kb_mc", lambda e: (
            e(_make_stack_op(op="push", value=_big_int_push(c))),
            e(_make_stack_op(op="opcode", code="OP_MUL")),
        ))
    # mod reduction — uses cached prime when available
    t.to_top("_kb_mc")
    t.raw_block(["_kb_mc"], result_name, lambda e: (
        t.emit_prime(e),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _kb_field_inv(t: KBTracker, a_name: str, result_name: str) -> None:
    """Compute a^(p-2) mod p via square-and-multiply (Fermat's little theorem).

    p-2 = 2130706431 = 0x7eFFFFFF = 0b0111_1110_1111_1111_1111_1111_1111_1111
    31 bits, popcount 30.
    ~30 squarings + ~29 multiplies = ~59 compound operations.
    """
    # Start: result = a (for MSB bit 30 = 1)
    t.copy_to_top(a_name, "_inv_r")

    # Process bits 29 down to 0 (30 bits)
    p_minus_2 = KB_P_MINUS_2
    for i in range(29, -1, -1):
        # Always square
        _kb_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")

        # Multiply if bit is set
        if (p_minus_2 >> i) & 1:
            t.copy_to_top(a_name, "_inv_a")
            _kb_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")

    # Clean up original input and rename result
    t.to_top(a_name)
    t.drop()
    t.to_top("_inv_r")
    t.rename(result_name)


# ===========================================================================
# Public emit functions -- entry points called from stack.py
# ===========================================================================

def emit_kb_field_add(emit: Callable[["StackOp"], None]) -> None:
    """KoalaBear field addition.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a + b) mod p]
    """
    t = KBTracker(["a", "b"], emit)
    _kb_field_add(t, "a", "b", "result")


def emit_kb_field_sub(emit: Callable[["StackOp"], None]) -> None:
    """KoalaBear field subtraction.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a - b) mod p]
    """
    t = KBTracker(["a", "b"], emit)
    _kb_field_sub(t, "a", "b", "result")


def emit_kb_field_mul(emit: Callable[["StackOp"], None]) -> None:
    """KoalaBear field multiplication.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a * b) mod p]
    """
    t = KBTracker(["a", "b"], emit)
    _kb_field_mul(t, "a", "b", "result")


def emit_kb_field_inv(emit: Callable[["StackOp"], None]) -> None:
    """KoalaBear field multiplicative inverse.

    Stack in:  [..., a]
    Stack out: [..., a^(p-2) mod p]
    """
    t = KBTracker(["a"], emit)
    _kb_field_inv(t, "a", "result")


# ===========================================================================
# Ext4 field multiplication -- component emit functions
# ===========================================================================
# Quartic extension over KoalaBear using irreducible x^4 - 3 (W = 3).
# Given a = (a0, a1, a2, a3) and b = (b0, b1, b2, b3):
#   r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
#   r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
#   r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
#   r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
# Each emit function takes 8 args on stack: [a0, a1, a2, a3, b0, b1, b2, b3]
# and produces one component.


def _kb_ext4_mul_component(emit: Callable[["StackOp"], None], component: int) -> None:
    """Compute one component of ext4 multiplication."""
    t = KBTracker(["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"], emit)

    if component == 0:
        # r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b0", "_b0")
        _kb_field_mul(t, "_a0", "_b0", "_t0")     # a0*b0
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b3", "_b3")
        _kb_field_mul(t, "_a1", "_b3", "_t1")     # a1*b3
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b2", "_b2")
        _kb_field_mul(t, "_a2", "_b2", "_t2")     # a2*b2
        _kb_field_add(t, "_t1", "_t2", "_t12")    # a1*b3 + a2*b2
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b1", "_b1")
        _kb_field_mul(t, "_a3", "_b1", "_t3")     # a3*b1
        _kb_field_add(t, "_t12", "_t3", "_cross") # a1*b3 + a2*b2 + a3*b1
        _kb_field_mul_const(t, "_cross", KB_W, "_wcross")  # W * cross
        _kb_field_add(t, "_t0", "_wcross", "_r")  # a0*b0 + W*cross

    elif component == 1:
        # r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b1", "_b1")
        _kb_field_mul(t, "_a0", "_b1", "_t0")     # a0*b1
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b0", "_b0")
        _kb_field_mul(t, "_a1", "_b0", "_t1")     # a1*b0
        _kb_field_add(t, "_t0", "_t1", "_direct") # a0*b1 + a1*b0
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b3", "_b3")
        _kb_field_mul(t, "_a2", "_b3", "_t2")     # a2*b3
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b2", "_b2")
        _kb_field_mul(t, "_a3", "_b2", "_t3")     # a3*b2
        _kb_field_add(t, "_t2", "_t3", "_cross")  # a2*b3 + a3*b2
        _kb_field_mul_const(t, "_cross", KB_W, "_wcross")  # W * cross
        _kb_field_add(t, "_direct", "_wcross", "_r")

    elif component == 2:
        # r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3)
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b2", "_b2")
        _kb_field_mul(t, "_a0", "_b2", "_t0")     # a0*b2
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b1", "_b1")
        _kb_field_mul(t, "_a1", "_b1", "_t1")     # a1*b1
        _kb_field_add(t, "_t0", "_t1", "_sum01")
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b0", "_b0")
        _kb_field_mul(t, "_a2", "_b0", "_t2")     # a2*b0
        _kb_field_add(t, "_sum01", "_t2", "_direct")
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b3", "_b3")
        _kb_field_mul(t, "_a3", "_b3", "_t3")     # a3*b3
        _kb_field_mul_const(t, "_t3", KB_W, "_wcross")  # W * a3*b3
        _kb_field_add(t, "_direct", "_wcross", "_r")

    elif component == 3:
        # r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0
        t.copy_to_top("a0", "_a0"); t.copy_to_top("b3", "_b3")
        _kb_field_mul(t, "_a0", "_b3", "_t0")     # a0*b3
        t.copy_to_top("a1", "_a1"); t.copy_to_top("b2", "_b2")
        _kb_field_mul(t, "_a1", "_b2", "_t1")     # a1*b2
        _kb_field_add(t, "_t0", "_t1", "_sum01")
        t.copy_to_top("a2", "_a2"); t.copy_to_top("b1", "_b1")
        _kb_field_mul(t, "_a2", "_b1", "_t2")     # a2*b1
        _kb_field_add(t, "_sum01", "_t2", "_sum012")
        t.copy_to_top("a3", "_a3"); t.copy_to_top("b0", "_b0")
        _kb_field_mul(t, "_a3", "_b0", "_t3")     # a3*b0
        _kb_field_add(t, "_sum012", "_t3", "_r")

    else:
        raise RuntimeError(f"Invalid ext4 component: {component}")

    # Clean up: drop the 8 input values, keep only _r
    for name in ["a0", "a1", "a2", "a3", "b0", "b1", "b2", "b3"]:
        t.to_top(name)
        t.drop()
    t.to_top("_r")
    t.rename("result")


def emit_kb_ext4_mul_0(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 mul component 0: r0 = a0*b0 + W*(a1*b3 + a2*b2 + a3*b1) mod p.

    Stack in:  [..., a0, a1, a2, a3, b0, b1, b2, b3]
    Stack out: [..., r0]
    """
    _kb_ext4_mul_component(emit, 0)


def emit_kb_ext4_mul_1(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 mul component 1: r1 = a0*b1 + a1*b0 + W*(a2*b3 + a3*b2) mod p.

    Stack in:  [..., a0, a1, a2, a3, b0, b1, b2, b3]
    Stack out: [..., r1]
    """
    _kb_ext4_mul_component(emit, 1)


def emit_kb_ext4_mul_2(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 mul component 2: r2 = a0*b2 + a1*b1 + a2*b0 + W*(a3*b3) mod p.

    Stack in:  [..., a0, a1, a2, a3, b0, b1, b2, b3]
    Stack out: [..., r2]
    """
    _kb_ext4_mul_component(emit, 2)


def emit_kb_ext4_mul_3(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 mul component 3: r3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 mod p.

    Stack in:  [..., a0, a1, a2, a3, b0, b1, b2, b3]
    Stack out: [..., r3]
    """
    _kb_ext4_mul_component(emit, 3)


# ===========================================================================
# Ext4 field inverse -- component emit functions
# ===========================================================================
# Inverse via tower of quadratic extensions.
# Given a = (a0, a1, a2, a3):
#   norm0 = a0^2 + W*a2^2 - 2*W*a1*a3
#   norm1 = 2*a0*a2 - a1^2 - W*a3^2
#   det   = norm0^2 - W*norm1^2
#   scalar = inv(det)
#   invN0  = norm0 * scalar
#   invN1  = -norm1 * scalar    (field negation)
# Then:
#   r0 =  a0*invN0 + W*a2*invN1
#   r1 = -(a1*invN0 + W*a3*invN1)
#   r2 =  a0*invN1 + a2*invN0
#   r3 = -(a1*invN1 + a3*invN0)


def _kb_ext4_inv_common(t: KBTracker) -> None:
    """Shared inverse preamble: compute _inv_n0 and _inv_n1 from a0..a3.

    Expects stack names: a0, a1, a2, a3.
    After this call, the tracker has: a0, a1, a2, a3, _inv_n0, _inv_n1
    (plus intermediate values).

    IMPORTANT: All uses of a0..a3 go through copy_to_top so the originals
    are preserved for the per-component functions.
    """
    # Step 1: Compute norm_0 = a0^2 + W*a2^2 - 2*W*a1*a3
    t.copy_to_top("a0", "_a0c")
    _kb_field_sqr(t, "_a0c", "_a0sq")           # a0^2
    t.copy_to_top("a2", "_a2c")
    _kb_field_sqr(t, "_a2c", "_a2sq")           # a2^2
    _kb_field_mul_const(t, "_a2sq", KB_W, "_wa2sq")  # W*a2^2
    _kb_field_add(t, "_a0sq", "_wa2sq", "_n0a")      # a0^2 + W*a2^2
    t.copy_to_top("a1", "_a1c")
    t.copy_to_top("a3", "_a3c")
    _kb_field_mul(t, "_a1c", "_a3c", "_a1a3")   # a1*a3
    _kb_field_mul_const(t, "_a1a3", 2 * KB_W, "_2wa1a3")  # 2*W*a1*a3
    _kb_field_sub(t, "_n0a", "_2wa1a3", "_norm0")  # norm_0

    # Step 2: Compute norm_1 = 2*a0*a2 - a1^2 - W*a3^2
    t.copy_to_top("a0", "_a0d")
    t.copy_to_top("a2", "_a2d")
    _kb_field_mul(t, "_a0d", "_a2d", "_a0a2")   # a0*a2
    _kb_field_mul_const(t, "_a0a2", 2, "_2a0a2")  # 2*a0*a2
    t.copy_to_top("a1", "_a1d")
    _kb_field_sqr(t, "_a1d", "_a1sq")           # a1^2
    _kb_field_sub(t, "_2a0a2", "_a1sq", "_n1a")  # 2*a0*a2 - a1^2
    t.copy_to_top("a3", "_a3d")
    _kb_field_sqr(t, "_a3d", "_a3sq")           # a3^2
    _kb_field_mul_const(t, "_a3sq", KB_W, "_wa3sq")  # W*a3^2
    _kb_field_sub(t, "_n1a", "_wa3sq", "_norm1")  # norm_1

    # Step 3: Quadratic inverse: scalar = (norm_0^2 - W*norm_1^2)^(-1)
    t.copy_to_top("_norm0", "_n0copy")
    _kb_field_sqr(t, "_n0copy", "_n0sq")        # norm_0^2
    t.copy_to_top("_norm1", "_n1copy")
    _kb_field_sqr(t, "_n1copy", "_n1sq")        # norm_1^2
    _kb_field_mul_const(t, "_n1sq", KB_W, "_wn1sq")  # W*norm_1^2
    _kb_field_sub(t, "_n0sq", "_wn1sq", "_det")  # norm_0^2 - W*norm_1^2
    _kb_field_inv(t, "_det", "_scalar")          # scalar = det^(-1)

    # Step 4: inv_n0 = norm_0 * scalar, inv_n1 = -norm_1 * scalar
    t.copy_to_top("_scalar", "_sc0")
    _kb_field_mul(t, "_norm0", "_sc0", "_inv_n0")  # inv_n0 = norm_0 * scalar

    # -norm_1 = (p - norm_1) mod p
    t.copy_to_top("_norm1", "_neg_n1_pre")
    t.push_int("_pval", KB_P)
    t.to_top("_neg_n1_pre")
    t.raw_block(["_pval", "_neg_n1_pre"], "_neg_n1_sub", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_SUB")),
    ))
    _kb_field_mod(t, "_neg_n1_sub", "_neg_norm1")
    _kb_field_mul(t, "_neg_norm1", "_scalar", "_inv_n1")


def _kb_ext4_inv_component(emit: Callable[["StackOp"], None], component: int) -> None:
    """Compute one component of ext4 inverse."""
    t = KBTracker(["a0", "a1", "a2", "a3"], emit)
    _kb_ext4_inv_common(t)

    if component == 0:
        # r0 = a0*inv_n0 + W*a2*inv_n1
        t.copy_to_top("a0", "_ea0")
        t.copy_to_top("_inv_n0", "_ein0")
        _kb_field_mul(t, "_ea0", "_ein0", "_ep0")   # a0*inv_n0
        t.copy_to_top("a2", "_ea2")
        t.copy_to_top("_inv_n1", "_ein1")
        _kb_field_mul(t, "_ea2", "_ein1", "_ep1")   # a2*inv_n1
        _kb_field_mul_const(t, "_ep1", KB_W, "_wep1")  # W*a2*inv_n1
        _kb_field_add(t, "_ep0", "_wep1", "_r")

    elif component == 1:
        # r1 = -(a1*inv_n0 + W*a3*inv_n1)
        t.copy_to_top("a1", "_oa1")
        t.copy_to_top("_inv_n0", "_oin0")
        _kb_field_mul(t, "_oa1", "_oin0", "_op0")   # a1*inv_n0
        t.copy_to_top("a3", "_oa3")
        t.copy_to_top("_inv_n1", "_oin1")
        _kb_field_mul(t, "_oa3", "_oin1", "_op1")   # a3*inv_n1
        _kb_field_mul_const(t, "_op1", KB_W, "_wop1")  # W*a3*inv_n1
        _kb_field_add(t, "_op0", "_wop1", "_odd0")
        # Negate: r = (0 - odd0) mod p
        t.push_int("_zero1", 0)
        _kb_field_sub(t, "_zero1", "_odd0", "_r")

    elif component == 2:
        # r2 = a0*inv_n1 + a2*inv_n0
        t.copy_to_top("a0", "_ea0")
        t.copy_to_top("_inv_n1", "_ein1")
        _kb_field_mul(t, "_ea0", "_ein1", "_ep0")   # a0*inv_n1
        t.copy_to_top("a2", "_ea2")
        t.copy_to_top("_inv_n0", "_ein0")
        _kb_field_mul(t, "_ea2", "_ein0", "_ep1")   # a2*inv_n0
        _kb_field_add(t, "_ep0", "_ep1", "_r")

    elif component == 3:
        # r3 = -(a1*inv_n1 + a3*inv_n0)
        t.copy_to_top("a1", "_oa1")
        t.copy_to_top("_inv_n1", "_oin1")
        _kb_field_mul(t, "_oa1", "_oin1", "_op0")   # a1*inv_n1
        t.copy_to_top("a3", "_oa3")
        t.copy_to_top("_inv_n0", "_oin0")
        _kb_field_mul(t, "_oa3", "_oin0", "_op1")   # a3*inv_n0
        _kb_field_add(t, "_op0", "_op1", "_odd1")
        # Negate: r = (0 - odd1) mod p
        t.push_int("_zero3", 0)
        _kb_field_sub(t, "_zero3", "_odd1", "_r")

    else:
        raise RuntimeError(f"Invalid ext4 component: {component}")

    # Clean up: drop all remaining except _r
    remaining = [n for n in t.nm if n is not None and n != "_r"]
    for name in remaining:
        t.to_top(name)
        t.drop()
    t.to_top("_r")
    t.rename("result")


def emit_kb_ext4_inv_0(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 inv component 0: r0 = a0*inv_n0 + W*a2*inv_n1 mod p.

    Stack in:  [..., a0, a1, a2, a3]
    Stack out: [..., r0]
    """
    _kb_ext4_inv_component(emit, 0)


def emit_kb_ext4_inv_1(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 inv component 1: r1 = -(a1*inv_n0 + W*a3*inv_n1) mod p.

    Stack in:  [..., a0, a1, a2, a3]
    Stack out: [..., r1]
    """
    _kb_ext4_inv_component(emit, 1)


def emit_kb_ext4_inv_2(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 inv component 2: r2 = a0*inv_n1 + a2*inv_n0 mod p.

    Stack in:  [..., a0, a1, a2, a3]
    Stack out: [..., r2]
    """
    _kb_ext4_inv_component(emit, 2)


def emit_kb_ext4_inv_3(emit: Callable[["StackOp"], None]) -> None:
    """Ext4 inv component 3: r3 = -(a1*inv_n1 + a3*inv_n0) mod p.

    Stack in:  [..., a0, a1, a2, a3]
    Stack out: [..., r3]
    """
    _kb_ext4_inv_component(emit, 3)


# ===========================================================================
# Dispatch table
# ===========================================================================

KB_DISPATCH: dict[str, Callable[[Callable[["StackOp"], None]], None]] = {
    "kbFieldAdd": emit_kb_field_add,
    "kbFieldSub": emit_kb_field_sub,
    "kbFieldMul": emit_kb_field_mul,
    "kbFieldInv": emit_kb_field_inv,
    "kbExt4Mul0": emit_kb_ext4_mul_0,
    "kbExt4Mul1": emit_kb_ext4_mul_1,
    "kbExt4Mul2": emit_kb_ext4_mul_2,
    "kbExt4Mul3": emit_kb_ext4_mul_3,
    "kbExt4Inv0": emit_kb_ext4_inv_0,
    "kbExt4Inv1": emit_kb_ext4_inv_1,
    "kbExt4Inv2": emit_kb_ext4_inv_2,
    "kbExt4Inv3": emit_kb_ext4_inv_3,
}


def dispatch_kb_builtin(func_name: str, emit: Callable[["StackOp"], None]) -> None:
    """Dispatch a KoalaBear field builtin by name."""
    fn = KB_DISPATCH.get(func_name)
    if fn is None:
        raise RuntimeError(f"unknown KoalaBear builtin: {func_name}")
    fn(emit)
