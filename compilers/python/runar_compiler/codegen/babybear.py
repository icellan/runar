"""Baby Bear field arithmetic codegen -- Baby Bear prime field operations for Bitcoin Script.

Follows the ec.py pattern: self-contained module imported by stack.py.
Uses a BBTracker for named stack state tracking.

Baby Bear prime: p = 2^31 - 2^27 + 1 = 2013265921
Used by SP1 STARK proofs (FRI verification).

All values fit in a single BSV script number (31-bit prime).
No multi-limb arithmetic needed.

Direct port of ``packages/runar-compiler/src/passes/babybear-codegen.ts``.
"""

from __future__ import annotations

from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from runar_compiler.codegen.stack import StackOp, PushValue

# ===========================================================================
# Constants
# ===========================================================================

# Baby Bear field prime p = 2^31 - 2^27 + 1
BB_P: int = 2013265921
# p - 2, used for Fermat's little theorem modular inverse
BB_P_MINUS_2: int = BB_P - 2


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
# BBTracker -- named stack state tracker (mirrors ECTracker / TS BBTracker)
# ===========================================================================

class BBTracker:
    """Tracks named stack positions and emits StackOps for Baby Bear codegen."""

    def __init__(self, init: list[str], emit: Callable[["StackOp"], None]) -> None:
        self.nm: list[str] = list(init)
        self.e = emit

    @property
    def depth(self) -> int:
        return len(self.nm)

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"BBTracker: '{name}' not on stack {self.nm}")

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


# ===========================================================================
# Field arithmetic internals
# ===========================================================================

def _bb_field_mod(t: BBTracker, a_name: str, result_name: str) -> None:
    """Reduce value mod p, ensuring non-negative result.

    Pattern: (a % p + p) % p
    """
    t.to_top(a_name)
    t.raw_block([a_name], result_name, lambda e: (
        e(_make_stack_op(op="push", value=_big_int_push(BB_P))),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
        e(_make_stack_op(op="push", value=_big_int_push(BB_P))),
        e(_make_stack_op(op="opcode", code="OP_ADD")),
        e(_make_stack_op(op="push", value=_big_int_push(BB_P))),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _bb_field_add(t: BBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a + b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_bb_add", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_ADD")),
    ))
    # Sum of two values in [0, p-1] is always non-negative, so simple OP_MOD suffices
    t.to_top("_bb_add")
    t.raw_block(["_bb_add"], result_name, lambda e: (
        e(_make_stack_op(op="push", value=_big_int_push(BB_P))),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _bb_field_sub(t: BBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a - b) mod p (non-negative)."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_bb_diff", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_SUB")),
    ))
    # Difference can be negative, need full mod-reduce
    _bb_field_mod(t, "_bb_diff", result_name)


def _bb_field_mul(t: BBTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a * b) mod p."""
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_bb_prod", lambda e: (
        e(_make_stack_op(op="opcode", code="OP_MUL")),
    ))
    # Product of two non-negative values is non-negative, simple OP_MOD
    t.to_top("_bb_prod")
    t.raw_block(["_bb_prod"], result_name, lambda e: (
        e(_make_stack_op(op="push", value=_big_int_push(BB_P))),
        e(_make_stack_op(op="opcode", code="OP_MOD")),
    ))


def _bb_field_sqr(t: BBTracker, a_name: str, result_name: str) -> None:
    """Compute (a * a) mod p."""
    t.copy_to_top(a_name, "_bb_sqr_copy")
    _bb_field_mul(t, a_name, "_bb_sqr_copy", result_name)


def _bb_field_inv(t: BBTracker, a_name: str, result_name: str) -> None:
    """Compute a^(p-2) mod p via square-and-multiply (Fermat's little theorem).

    p-2 = 2013265919 = 0b111_0111_1111_1111_1111_1111_1111_1111
    31 bits, popcount 28.
    ~30 squarings + ~27 multiplies = ~57 compound operations.
    """
    # Start: result = a (for MSB bit 30 = 1)
    t.copy_to_top(a_name, "_inv_r")

    # Process bits 29 down to 0 (30 bits)
    p_minus_2 = BB_P_MINUS_2
    for i in range(29, -1, -1):
        # Always square
        _bb_field_sqr(t, "_inv_r", "_inv_r2")
        t.rename("_inv_r")

        # Multiply if bit is set
        if (p_minus_2 >> i) & 1:
            t.copy_to_top(a_name, "_inv_a")
            _bb_field_mul(t, "_inv_r", "_inv_a", "_inv_m")
            t.rename("_inv_r")

    # Clean up original input and rename result
    t.to_top(a_name)
    t.drop()
    t.to_top("_inv_r")
    t.rename(result_name)


# ===========================================================================
# Public emit functions -- entry points called from stack.py
# ===========================================================================

def emit_bb_field_add(emit: Callable[["StackOp"], None]) -> None:
    """Baby Bear field addition.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a + b) mod p]
    """
    t = BBTracker(["a", "b"], emit)
    _bb_field_add(t, "a", "b", "result")


def emit_bb_field_sub(emit: Callable[["StackOp"], None]) -> None:
    """Baby Bear field subtraction.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a - b) mod p]
    """
    t = BBTracker(["a", "b"], emit)
    _bb_field_sub(t, "a", "b", "result")


def emit_bb_field_mul(emit: Callable[["StackOp"], None]) -> None:
    """Baby Bear field multiplication.

    Stack in:  [..., a, b] (b on top)
    Stack out: [..., (a * b) mod p]
    """
    t = BBTracker(["a", "b"], emit)
    _bb_field_mul(t, "a", "b", "result")


def emit_bb_field_inv(emit: Callable[["StackOp"], None]) -> None:
    """Baby Bear field multiplicative inverse.

    Stack in:  [..., a]
    Stack out: [..., a^(p-2) mod p]
    """
    t = BBTracker(["a"], emit)
    _bb_field_inv(t, "a", "result")


# ===========================================================================
# Dispatch table
# ===========================================================================

BB_DISPATCH: dict[str, Callable[[Callable[["StackOp"], None]], None]] = {
    "bbFieldAdd": emit_bb_field_add,
    "bbFieldSub": emit_bb_field_sub,
    "bbFieldMul": emit_bb_field_mul,
    "bbFieldInv": emit_bb_field_inv,
}


def dispatch_bb_builtin(func_name: str, emit: Callable[["StackOp"], None]) -> None:
    """Dispatch a Baby Bear field builtin by name."""
    fn = BB_DISPATCH.get(func_name)
    if fn is None:
        raise RuntimeError(f"unknown Baby Bear builtin: {func_name}")
    fn(emit)
