"""EC codegen -- secp256k1 elliptic curve operations for Bitcoin Script.

Follows the slh_dsa.py pattern: self-contained module imported by stack.py.
Uses an ECTracker (similar to SLHTracker) for named stack state tracking.

Point representation: 64 bytes (x[32] || y[32], big-endian unsigned).
Internal arithmetic uses Jacobian coordinates for scalar multiplication.

Direct port of ``compilers/go/codegen/ec.go``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
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

# secp256k1 curve order
EC_CURVE_N: int = int("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)


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
# Codegen options and sign lattice
# ===========================================================================

@dataclass(frozen=True)
class EcCodegenOptions:
    """Codegen options shared by every EC / NIST-curve emitter.

    Off by default: with ``None`` (or an all-false instance) each emitter is
    byte-identical to what the seven tiers ship today, so no golden, size
    baseline, or cross-tier parity gate can move.
    """

    constant_pool: bool = False
    """Park large repeated constants (the field prime, the group order) in a
    stack slot and copy them with ``OP_PICK`` instead of re-pushing the literal.

    ``_ec_field_mod`` pushes the 256-bit prime at every modular reduction -- 34
    bytes a time, 20,025 times in ``p256-wallet`` (71 % of that fixture). A pick
    from a slot a dozen deep costs 2.
    """

    reduction_sinking: bool = False
    """Emit ``a mod p`` without the sign fix-up wherever the dividend is provably
    non-negative, and the cheap ``a - b + p`` form for subtraction wherever the
    subtrahend is provably reduced.

    Which reductions qualify is decided by the sign lattice below -- never
    assumed. Only useful alongside ``constant_pool``: the cheap subtraction
    references the prime twice, so without a pooled slot it does not pay (and the
    emitters compare the two costs, so it is never taken when it does not).
    """

    fixed_base_comb: bool = False
    """Use a fixed-base comb instead of the binary ladder wherever the base point
    is a compile-time constant (``ecMulGen``, ``p256MulGen``, ``p384MulGen``, and
    the ``u1*G`` half of ECDSA verification).

    The window width is not fixed here: the emitter renders each candidate and
    keeps whichever the byte-cost model scores smallest.
    """


class Dom(IntEnum):
    """What is known about a tracked value's sign and range.

    ``REDUCED`` implies ``NON_NEGATIVE``; the ordering is what the transfer
    functions meet over. ``UNKNOWN`` is the default for every slot the analysis
    has not explicitly proved something about -- including everything a
    ``raw_block`` or an ``OP_IF`` produces -- so an un-analysed value can only
    ever fall back to the shipping reduction.

    The distinction is not academic. ``OP_BIN2NUM`` of 32 unsigned coordinate
    bytes gives ``NON_NEGATIVE`` but NOT ``REDUCED``: a coordinate may
    legitimately be up to ``2^256 - 1`` while p is ``2^32 + 977`` smaller.
    Multiplication and addition need only ``NON_NEGATIVE``; subtraction's cheap
    form needs the subtrahend ``REDUCED``, and conflating the two produces a
    script that passes 256 EC oracle assertions and is still wrong on
    ``ecAdd((0,1), (2^256-1,1))``.
    """

    UNKNOWN = 0
    """Nothing known. May be negative."""
    NON_NEGATIVE = 1
    """Provably >= 0. May be >= p."""
    REDUCED = 2
    """Provably in [0, p)."""


def is_non_negative(d: Dom) -> bool:
    """True when *d* proves the value is >= 0."""
    return d >= Dom.NON_NEGATIVE


# Stack slot names reserved for pooled constants.
POOL_FIELD_P = "_pool$p"
POOL_GROUP_N = "_pool$n"


# ===========================================================================
# ECTracker -- named stack state tracker (mirrors TS ECTracker)
# ===========================================================================

class ECTracker:
    """Tracks named stack positions and emits StackOps for EC codegen."""

    def __init__(
        self,
        init: list[str],
        emit: Callable[["StackOp"], None],
        opts: "EcCodegenOptions | None" = None,
        init_domains: "list[Dom] | None" = None,
    ) -> None:
        self.nm: list[str] = list(init)
        # Sign-lattice fact per stack SLOT, kept parallel to `nm`.
        #
        # Slot-parallel rather than keyed by name on purpose: names are reused
        # (`_fmul_prod` is written by every multiply) and the same name can be
        # resident twice, so a name-keyed dict would go stale in exactly the
        # cases that matter. Every mutation of `nm` below mirrors into `dm` with
        # the same splice, so the two cannot drift.
        self.dm: list[Dom] = (list(init_domains) if init_domains is not None
                              else [Dom.UNKNOWN] * len(self.nm))
        # Lattice facts for values parked on the alt stack, bottom -> top.
        self.alt_dm: list[Dom] = []
        self.e = emit
        o = opts or EcCodegenOptions()
        self.pooling = o.constant_pool
        self.sinking = o.reduction_sinking
        self.comb = o.fixed_base_comb

    @property
    def options(self) -> EcCodegenOptions:
        """The options this tracker was built with, for a nested tracker."""
        return EcCodegenOptions(
            constant_pool=self.pooling,
            reduction_sinking=self.sinking,
            fixed_base_comb=self.comb,
        )

    # -- sign lattice -------------------------------------------------------

    def domain_of(self, name: str) -> Dom:
        """What is known about *name*. ``UNKNOWN`` when absent."""
        # A silent desync here would hand a transfer function a fact about the
        # WRONG slot, which is the one failure mode that produces a smaller
        # script that quietly computes something else. Fail loudly instead.
        if len(self.dm) != len(self.nm):
            raise RuntimeError(
                f"ECTracker: lattice desynchronised ({len(self.nm)} slots, "
                f"{len(self.dm)} facts). Every nm mutation must go through a "
                "tracker method or push_tracked/pop_tracked."
            )
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return self.dm[i]
        return Dom.UNKNOWN

    def set_domain(self, name: str, d: Dom) -> None:
        """Record a fact about *name*'s slot."""
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                self.dm[i] = d
                return

    def push_tracked(self, name: str, d: Dom = Dom.UNKNOWN) -> None:
        """Push a slot the caller tracks itself (where raw opcodes create items)."""
        self.nm.append(name)
        self.dm.append(d)

    def pop_tracked(self) -> str:
        """Pop a slot the caller tracks itself. Mirror of ``push_tracked``."""
        if not self.nm:
            return ""
        self.dm.pop()
        return self.nm.pop()

    def remove_slot_at(self, index: int) -> tuple[str, Dom]:
        """Remove the slot at an absolute (bottom-relative) index."""
        n = self.nm.pop(index)
        d = self.dm.pop(index)
        return (n, d)

    @property
    def depth(self) -> int:
        return len(self.nm)

    def find_depth(self, name: str) -> int:
        for i in range(len(self.nm) - 1, -1, -1):
            if self.nm[i] == name:
                return len(self.nm) - 1 - i
        raise RuntimeError(f"ECTracker: '{name}' not on stack {self.nm}")

    def push_bytes(self, n: str, v: bytes) -> None:
        self.e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=v)))
        # A byte blob is not a number until BIN2NUM decides how to read it.
        self.push_tracked(n, Dom.UNKNOWN)

    def push_big_int(self, n: str, v: int) -> None:
        self.e(_make_stack_op(op="push", value=_make_push_value(kind="bigint", big_int=v)))
        self.push_tracked(n, Dom.NON_NEGATIVE if v >= 0 else Dom.UNKNOWN)

    def push_int(self, n: str, v: int) -> None:
        self.e(_make_stack_op(op="push", value=_big_int_push(v)))
        self.push_tracked(n, Dom.NON_NEGATIVE if v >= 0 else Dom.UNKNOWN)

    def dup(self, n: str) -> None:
        self.e(_make_stack_op(op="dup"))
        self.push_tracked(n, self.dm[-1] if self.dm else Dom.UNKNOWN)

    def drop(self) -> None:
        self.e(_make_stack_op(op="drop"))
        self.pop_tracked()

    def nip(self) -> None:
        self.e(_make_stack_op(op="nip"))
        L = len(self.nm)
        if L >= 2:
            self.remove_slot_at(L - 2)

    def over(self, n: str) -> None:
        self.e(_make_stack_op(op="over"))
        self.push_tracked(n, self.dm[-2] if len(self.dm) >= 2 else Dom.UNKNOWN)

    def swap(self) -> None:
        self.e(_make_stack_op(op="swap"))
        L = len(self.nm)
        if L >= 2:
            self.nm[L - 1], self.nm[L - 2] = self.nm[L - 2], self.nm[L - 1]
            self.dm[L - 1], self.dm[L - 2] = self.dm[L - 2], self.dm[L - 1]

    def rot(self) -> None:
        self.e(_make_stack_op(op="rot"))
        L = len(self.nm)
        if L >= 3:
            r, rd = self.remove_slot_at(L - 3)
            self.push_tracked(r, rd)

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
        self.push_tracked("", Dom.NON_NEGATIVE)
        self.e(_make_stack_op(op="roll", depth=d))
        self.pop_tracked()  # the depth literal
        idx = len(self.nm) - 1 - d
        r, rd = self.remove_slot_at(idx)
        self.push_tracked(r, rd)

    def pick(self, d: int, n: str) -> None:
        if d == 0:
            self.dup(n)
            return
        if d == 1:
            self.over(n)
            return
        self.e(_make_stack_op(op="push", value=_big_int_push(d)))
        self.push_tracked("", Dom.NON_NEGATIVE)
        self.e(_make_stack_op(op="pick", depth=d))
        self.pop_tracked()  # the depth literal
        # Once the depth literal is gone the copied slot sits at depth d.
        src = self.dm[len(self.dm) - 1 - d] if len(self.dm) > d else Dom.UNKNOWN
        self.push_tracked(n, src)

    def to_top(self, name: str) -> None:
        self.roll(self.find_depth(name))

    def copy_to_top(self, name: str, n: str) -> None:
        self.pick(self.find_depth(name), n)

    # -- constant pool ------------------------------------------------------
    #
    # A pooled constant is an ordinary tracked slot; nothing about the stack
    # model changes. `push_const` just chooses, per call site and by emitted
    # bytes, between copying that slot and re-pushing the literal. Nested
    # trackers built from `list(t.nm)` inherit the slot for free, so pooled
    # constants work unchanged inside an `OP_IF` arm.

    def pool_constant(self, slot: str, value: int) -> None:
        """Park *value* in *slot* for this emitter. No-op when pooling is off."""
        if not self.pooling or slot in self.nm:
            return
        self.push_big_int(slot, value)

    def release_constant(self, slot: str) -> None:
        """Remove a pooled slot. No-op when pooling is off or the slot is absent."""
        if not self.pooling or slot not in self.nm:
            return
        self.to_top(slot)
        self.drop()

    def const_cost(self, slot: str, value: int) -> int:
        """Emitted bytes a ``push_const`` of this constant would cost right now.

        The comparison is exact -- ``size_of_push_int`` is the same encoder the
        emit pass uses -- so pooling can never make a call site bigger. A pick at
        depth d costs ``size_of_push_int(d) + 1``; depths 0 and 1 are OP_DUP /
        OP_OVER, 1 byte each.
        """
        from runar_compiler.codegen.cost_model import size_of_push_int

        if self.pooling and slot in self.nm:
            d = self.find_depth(slot)
            pick_cost = 1 if d <= 1 else size_of_push_int(d) + 1
            if pick_cost < size_of_push_int(value):
                return pick_cost
        return size_of_push_int(value)

    def push_const(self, slot: str, value: int, name: str) -> None:
        """Materialize *value* on top as *name*, from the pooled slot when that
        is cheaper in emitted bytes than pushing the literal."""
        from runar_compiler.codegen.cost_model import size_of_push_int

        if self.pooling and slot in self.nm:
            d = self.find_depth(slot)
            pick_cost = 1 if d <= 1 else size_of_push_int(d) + 1
            if pick_cost < size_of_push_int(value):
                self.pick(d, name)
                return
        self.push_big_int(name, value)

    def to_alt(self) -> None:
        self.op("OP_TOALTSTACK")
        if self.nm:
            d = self.dm[-1]
            self.pop_tracked()
            self.alt_dm.append(d)

    def from_alt(self, n: str) -> None:
        self.op("OP_FROMALTSTACK")
        d = self.alt_dm.pop() if self.alt_dm else Dom.UNKNOWN
        self.push_tracked(n, d)

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
            self.pop_tracked()
        fn(self.e)
        if produce:
            # Opaque opcodes: nothing is known about the result unless the caller
            # proves it and records that with `set_domain` afterwards.
            self.push_tracked(produce, Dom.UNKNOWN)

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
        self.pop_tracked()  # condition consumed
        then_ops: list["StackOp"] = []
        else_ops: list["StackOp"] = []
        then_fn(lambda op: then_ops.append(op))
        else_fn(lambda op: else_ops.append(op))
        self.e(_make_stack_op(op="if", then=then_ops, else_=else_ops))
        if result_name:
            # A join over two arms this tracker did not analyse: nothing is known.
            self.push_tracked(result_name, Dom.UNKNOWN)


# ===========================================================================
# Field arithmetic helpers
# ===========================================================================

def _ec_push_field_p(t: ECTracker, name: str) -> None:
    """Push the field prime p onto the stack as a script number."""
    t.push_const(POOL_FIELD_P, EC_FIELD_P, name)


def _ec_field_mod_short(t: ECTracker, a_name: str, result_name: str) -> None:
    """``a mod p`` with no sign fix-up: 1 opcode instead of 7.

    Sound only when the dividend is provably >= 0, because ``OP_MOD`` takes the
    sign of the dividend. The caller proves that; this does not check.
    """
    t.to_top(a_name)
    _ec_push_field_p(t, "_fmods_p")
    t.raw_block([a_name, "_fmods_p"], result_name,
                lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))
    t.set_domain(result_name, Dom.REDUCED)


def _ec_cheap_sub_pays(t: ECTracker) -> bool:
    """Does the cheap ``a - b + p`` subtraction shape pay here?

    It references the prime TWICE where the shipping shape references it once and
    pays six more opcodes, so it only wins when the prime is cheap to
    materialise -- i.e. when it is pooled. Without a pool this rewrite makes
    p256-wallet LARGER (958,792 -> 999,371 measured), which is why it is a cost
    comparison and not a flag.
    """
    c = t.const_cost(POOL_FIELD_P, EC_FIELD_P)
    return 2 * c + 2 < c + 8


def _ec_field_mod(t: ECTracker, a_name: str, result_name: str) -> None:
    """Reduce TOS mod p, ensuring non-negative result."""
    if t.sinking and is_non_negative(t.domain_of(a_name)):
        _ec_field_mod_short(t, a_name, result_name)
        return
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
    t.set_domain(result_name, Dom.REDUCED)


def _ec_field_add(t: ECTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a + b) mod p."""
    # Read the operand facts BEFORE raw_block consumes their slots.
    sum_non_neg = is_non_negative(t.domain_of(a_name)) and is_non_negative(t.domain_of(b_name))
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fadd_sum", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    if sum_non_neg:
        t.set_domain("_fadd_sum", Dom.NON_NEGATIVE)
    _ec_field_mod(t, "_fadd_sum", result_name)


def _ec_field_sub(t: ECTracker, a_name: str, b_name: str, result_name: str) -> None:
    """Compute (a - b) mod p (non-negative)."""
    t.to_top(a_name)
    t.to_top(b_name)
    # The cheap shape needs a >= 0 AND b in [0, p): then a - b > -p, so a single
    # shifted reduction is exact. `b >= 0` alone is NOT enough -- a coordinate
    # decoded from 32 unsigned bytes can exceed p by up to 2^32 + 977, which is
    # precisely the ecAdd((0,1), (2^256-1,1)) counterexample.
    cheap = (t.sinking
             and is_non_negative(t.domain_of(a_name))
             and t.domain_of(b_name) == Dom.REDUCED
             and _ec_cheap_sub_pays(t))

    t.raw_block([a_name, b_name], "_fsub_diff", lambda e: e(_make_stack_op(op="opcode", code="OP_SUB")))

    if cheap:
        _ec_push_field_p(t, "_fsub_p")
        t.raw_block(["_fsub_diff", "_fsub_p"], "_fsub_shift",
                    lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
        t.set_domain("_fsub_shift", Dom.NON_NEGATIVE)
        _ec_field_mod_short(t, "_fsub_shift", result_name)
        return
    _ec_field_mod(t, "_fsub_diff", result_name)


def _ec_field_mul(t: ECTracker, a_name: str, b_name: str, result_name: str,
                  product_non_negative: bool = False) -> None:
    """Compute (a * b) mod p.

    *product_non_negative* lets a caller assert the product's sign independently
    of the operands -- ``_ec_field_sqr`` uses it, since a*a >= 0 for any a.
    """
    non_neg = product_non_negative or (
        is_non_negative(t.domain_of(a_name)) and is_non_negative(t.domain_of(b_name)))
    t.to_top(a_name)
    t.to_top(b_name)
    t.raw_block([a_name, b_name], "_fmul_prod", lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
    if non_neg:
        t.set_domain("_fmul_prod", Dom.NON_NEGATIVE)
    _ec_field_mod(t, "_fmul_prod", result_name)


def _ec_field_mul_const(t: ECTracker, a_name: str, c: int, result_name: str) -> None:
    """Compute (a * c) mod p where c is a small constant."""
    # Every call site passes a small positive c, so the product keeps a's sign.
    non_neg = c > 0 and is_non_negative(t.domain_of(a_name))
    t.to_top(a_name)

    def _fmc_body(e: Callable[["StackOp"], None]) -> None:
        if c == 2:
            # Use OP_2MUL (single opcode, no push needed)
            e(_make_stack_op(op="opcode", code="OP_2MUL"))
        else:
            e(_make_stack_op(op="push", value=_big_int_push(c)))
            e(_make_stack_op(op="opcode", code="OP_MUL"))

    t.raw_block([a_name], "_fmc_prod", _fmc_body)
    if non_neg:
        t.set_domain("_fmc_prod", Dom.NON_NEGATIVE)
    _ec_field_mod(t, "_fmc_prod", result_name)


def _ec_field_sqr(t: ECTracker, a_name: str, result_name: str) -> None:
    """Compute (a * a) mod p. A square is non-negative whatever a's sign is."""
    t.copy_to_top(a_name, "_fsqr_copy")
    _ec_field_mul(t, a_name, "_fsqr_copy", result_name, product_non_negative=True)


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
    t.push_tracked("_dp_xb", Dom.UNKNOWN)
    t.push_tracked("_dp_yb", Dom.UNKNOWN)

    # Convert y_bytes (on top) to num
    # Reverse from BE to LE, append 0x00 sign byte to ensure unsigned, then BIN2NUM
    def _convert_y(e: Callable) -> None:
        _ec_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_yb"], y_name, _convert_y)
    # A 0x00 sign byte is appended before BIN2NUM, so the coordinate decodes
    # UNSIGNED: >= 0, but it may be up to 2^256 - 1 and therefore >= p. That gap
    # is exactly what the subtraction precondition turns on.
    t.set_domain(y_name, Dom.NON_NEGATIVE)

    # Convert x_bytes to num
    t.to_top("_dp_xb")
    def _convert_x(e: Callable) -> None:
        _ec_emit_reverse32(e)
        e(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=b"\x00")))
        e(_make_stack_op(op="opcode", code="OP_CAT"))
        e(_make_stack_op(op="opcode", code="OP_BIN2NUM"))
    t.raw_block(["_dp_xb"], x_name, _convert_x)
    t.set_domain(x_name, Dom.NON_NEGATIVE)

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
    # The chord slope s = (qy - py) / (qx - px) is undefined when P == Q: the
    # denominator is zero and the correct slope is the TANGENT, 3px^2 / (2py).
    # Without this, ecAdd(P, P) silently produced a wrong point, so every
    # contract that doubled deployed an unspendable script.
    #
    # Both cases are `s = num / den`, so only the NUMERATOR and DENOMINATOR are
    # selected and the single expensive field_inv still runs exactly once.
    # rx and ry below are already correct for doubling.
    #
    #   cond   = (px == qx) AND (py == qy)     1 when doubling, else 0
    #   num    = cond ? 3*px^2 : (qy - py)
    #   den    = cond ? 2*py   : (qx - px)
    #
    # selected as `b + cond*(a - b)`, which needs no branch and keeps the
    # emitted op sequence identical on both paths.
    #
    # THE THIRD CASE, P == -Q: px == qx but py != qy. Testing px == qx ALONE
    # sends it down the tangent path and returns 2P -- an on-curve, entirely
    # plausible, WRONG point. Before the doubling fix the chord path ran there,
    # divided by zero (_ec_field_inv is Fermat, inv(0) = 0) and produced an
    # OFF-curve blob, so `assert(ecOnCurve(ecAdd(a, b)))` -- the idiom this
    # codegen tells authors to write -- happened to reject it. Selecting on px
    # alone would have silently disarmed that.
    #
    # P + (-P) is the point at infinity, which affine x||y cannot represent.
    # This codegen already has a representation for O: the ALL-ZERO blob, which
    # is what `ecMul(P, 0n)` returns and what the `ec-mulgen-linear` rewrite in
    # optimizer/ec-rules.json produces for k1 + k2 == 0 (mod n). So return that,
    # by masking the result with `notinf = NOT(px == qx AND NOT cond)`:
    #
    #   - it agrees with the rewrite, so the same source cannot give two answers
    #     depending on whether the optimizer fired;
    #   - O is not on the curve (0^2 != 0^3 + 7), so the on-curve gate rejects
    #     it and the idiom above works again;
    #   - it adds no failure channel to what is a pure value-producing
    #     expression, the same reason _ec_emit_scalar_reduce reduces instead of
    #     rejecting.
    #
    # The mask is a bare OP_MUL with no reduction: rx, ry are already in [0, p)
    # and notinf is 0 or 1, so the product is canonical either way.
    t.copy_to_top("px", "_px_eq")
    t.copy_to_top("qx", "_qx_eq")

    def _eq(e: Callable[["StackOp"], None]) -> None:
        e(_make_stack_op(op="opcode", code="OP_NUMEQUAL"))

    t.raw_block(["_px_eq", "_qx_eq"], "_xeq", _eq)
    t.copy_to_top("py", "_py_eq")
    t.copy_to_top("qy", "_qy_eq")
    t.raw_block(["_py_eq", "_qy_eq"], "_yeq", _eq)
    t.copy_to_top("_xeq", "_xeq_c")
    t.to_top("_yeq")
    t.raw_block(["_xeq_c", "_yeq"], "_cond",
                lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # notinf = NOT(xeq - cond): xeq - cond is 1 exactly when px == qx and the
    # points are not equal, i.e. exactly the P == -Q case.
    t.to_top("_xeq")
    t.copy_to_top("_cond", "_cond_c")

    def _sub_not(e: Callable[["StackOp"], None]) -> None:
        e(_make_stack_op(op="opcode", code="OP_SUB"))
        e(_make_stack_op(op="opcode", code="OP_NOT"))

    t.raw_block(["_xeq", "_cond_c"], "_notinf", _sub_not)

    # chord numerator / denominator
    t.copy_to_top("qy", "_qy1")
    t.copy_to_top("py", "_py1")
    _ec_field_sub(t, "_qy1", "_py1", "_num_chord")
    t.copy_to_top("qx", "_qx1")
    t.copy_to_top("px", "_px1")
    _ec_field_sub(t, "_qx1", "_px1", "_den_chord")

    # tangent numerator / denominator: 3*px^2 and 2*py
    t.copy_to_top("px", "_px_t")
    _ec_field_sqr(t, "_px_t", "_px_sq")
    _ec_field_mul_const(t, "_px_sq", 3, "_num_tan")
    t.copy_to_top("py", "_py_t")
    _ec_field_mul_const(t, "_py_t", 2, "_den_tan")

    # num = num_chord + cond*(num_tan - num_chord)
    t.copy_to_top("_num_chord", "_num_chord_c")
    _ec_field_sub(t, "_num_tan", "_num_chord_c", "_num_diff")
    t.copy_to_top("_cond", "_cond_n")
    _ec_field_mul(t, "_num_diff", "_cond_n", "_num_sel")
    _ec_field_add(t, "_num_chord", "_num_sel", "_s_num")

    # den = den_chord + cond*(den_tan - den_chord)
    t.copy_to_top("_den_chord", "_den_chord_c")
    _ec_field_sub(t, "_den_tan", "_den_chord_c", "_den_diff")
    t.to_top("_cond")
    t.rename("_cond_d")
    _ec_field_mul(t, "_den_diff", "_cond_d", "_den_sel")
    _ec_field_add(t, "_den_chord", "_den_sel", "_s_den")

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
    _ec_field_mul_const(t, "_B1", 2, "_2B")
    _ec_field_sub(t, "_D2", "_2B", "_nx")

    # ny = D*(B - nx) - C
    t.copy_to_top("_nx", "_nx_copy")
    _ec_field_sub(t, "_B_save", "_nx_copy", "_B_nx")
    _ec_field_mul(t, "_D_save", "_B_nx", "_D_B_nx")
    _ec_field_sub(t, "_D_B_nx", "_C", "_ny")

    # nz = 2 * Y * Z
    _ec_field_mul(t, "_jy_save", "_jz_save", "_yz")
    _ec_field_mul_const(t, "_yz", 2, "_nz")

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
    # The inner tracker inherits the stack state AND the lattice facts: the
    # operands' proved domains are what decide which reduction shape the body
    # emits, so dropping them here would silently fall back everywhere.
    _ec_jacobian_add_affine_body(
        ECTracker(list(t.nm), e, t.options, list(t.dm)), False)


def _ec_jacobian_add_affine_body(it: ECTracker, keep_hr: bool) -> None:
    """The mixed-add itself, emitting through a tracker the caller owns.

    ``keep_hr`` additionally leaves copies of H and R on the stack. They are the
    exception detector: H = U2 - X1 and R = S2 - Y1 are both zero exactly when
    the Jacobian accumulator is the same curve point as the affine operand, the
    one case these formulas cannot compute (see
    _ec_build_jacobian_add_or_double_inline).
    """
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

    if keep_hr:
        it.copy_to_top("_H", "_H_keep")
        it.copy_to_top("_R", "_R_keep")

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
    _ec_field_mul_const(it, "_U1H2", 2, "_2U1H2")
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


def _ec_select_coord(
    t: ECTracker, add_name: str, dbl_name: str, cond_name: str, result_name: str
) -> None:
    """Branchless select of one Jacobian coordinate: ``add + cond*(dbl - add)``.

    Same shape as the numerator/denominator select in _ec_affine_add, so both
    paths emit the identical op sequence and the tracker's static stack model
    holds. Consumes add_name, dbl_name and cond_name.
    """
    t.copy_to_top(add_name, "_sel_add_c")
    _ec_field_sub(t, dbl_name, "_sel_add_c", "_sel_diff")
    _ec_field_mul(t, "_sel_diff", cond_name, "_sel_scaled")
    _ec_field_add(t, add_name, "_sel_scaled", result_name)


def _ec_build_jacobian_add_or_double_inline(e: Callable, t: ECTracker) -> None:
    """The ladder's LAST conditional step: mixed-add, but correct when the
    accumulator already equals the point being added.

    The Jacobian mixed-add cannot double. It computes H = U2 - X1, and when the
    two operands are the same curve point H = 0, so Z3 = Z1*H = 0 -- the point
    at infinity -- and since _ec_field_inv is Fermat (inv(0) = 0),
    _ec_jacobian_to_affine turns that into the ALL-ZERO point instead of 2P.
    ecMul(P, 2n) and ecMulGen(2n) returned 64 zero bytes.

    WHY ONLY THE LAST STEP. After step i the accumulator holds c_i*P where
    c_i = k' >> i and k' = k + 3n, so the conditional step adds P to
    (c_i - 1)*P. secp256k1 has cofactor 1, so P has order n and the degenerate
    cases are exactly c_i == 2 (mod n) -- accumulator == P -- and c_i == 0 or 1
    (mod n) -- accumulator == -P or O. c_i ranges over a CONTIGUOUS interval
    determined only by i, so this is decidable by interval arithmetic rather
    than by sampling, and over the whole domain k in [0, n-1] only two steps
    qualify, both at i = 0:

      k = 2  ->  c_0 = 3n+2 == 2, odd, so the add runs: accumulator == P. <- bug
      k = 0  ->  c_0 = 3n   == 0, odd, so the add runs: accumulator == -P,
                 true result the point at infinity, which affine coordinates
                 cannot represent; it stays the all-zero point, as before.

    At i >= 1, c_i lies in [3n>>i, (4n-1)>>i] -- the lower bound is 3n, not
    3n+1, because the reduce puts k = 0 in the domain -- and that interval
    contains no value == 0, 1 or 2 (mod n) that is also odd; c_256 = 2 is even,
    so no add runs. Handling H == 0 at every one of the 257 steps would cost
    ~70% more script bytes; handling it here costs 0.26%. The operand P is
    caller-supplied but cannot move the exception, because the condition depends
    only on c_i mod ord(P) and ord(P) = n for every point on the curve. Points
    that are NOT on the curve carry no such guarantee -- gate untrusted input on
    ecOnCurve first.

    THE ENTIRE ARGUMENT IS CONDITIONED ON k in [0, n-1], which is only true
    because emit_ec_mul reduces k mod n before adding 3n. That reduce landed one
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

    _ec_jacobian_add_affine_body(it, True)

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

    # Move the add result aside so _ec_jacobian_double can work on jx/jy/jz
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
    _ec_jacobian_double(it)
    it.to_top("jx")
    it.rename("_dbl_x")
    it.to_top("jy")
    it.rename("_dbl_y")
    it.to_top("jz")
    it.rename("_dbl_z")

    it.copy_to_top("_cond", "_cond_x")
    _ec_select_coord(it, "_add_x", "_dbl_x", "_cond_x", "jx")
    it.copy_to_top("_cond", "_cond_y")
    _ec_select_coord(it, "_add_y", "_dbl_y", "_cond_y", "jy")
    it.to_top("_cond")
    it.rename("_cond_z")
    _ec_select_coord(it, "_add_z", "_dbl_z", "_cond_z", "jz")


# ===========================================================================
# Public entry points (called from stack lowerer)
# ===========================================================================

def emit_ec_add(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Add two points.

    Stack in: [point_a, point_b] (b on top)
    Stack out: [result_point]
    """
    t = ECTracker(["_pa", "_pb"], emit, opts)
    t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
    _ec_decompose_point(t, "_pa", "px", "py")
    _ec_decompose_point(t, "_pb", "qx", "qy")
    _ec_affine_add(t)
    _ec_compose_point(t, "rx", "ry", "_result")
    t.release_constant(POOL_FIELD_P)


def _ec_emit_scalar_reduce(t: ECTracker, k_name: str, result_name: str, curve_n: int) -> None:
    """Reduce a scalar to [0, n-1]: ((k mod n) + n) mod n.

    OP_MOD takes the sign of the DIVIDEND, so ``k mod n`` alone lands in
    (-n, n); the ``+ n, mod n`` normalises the negative half. One push of n
    covers both reductions -- the same shape as ``emit_ec_mod_reduce``.

    Without it, ``emit_ec_mul``'s ladder is only correct while
    2^257 <= k + 3n < 2^258: a scalar >= ~n sets bit 258, the 257-iteration
    loop never sees it, and the ladder returns a DIFFERENT multiple of P rather
    than failing. Scalars are contract input, so that is attacker-chosen.
    Reducing costs 1 push + 8 opcodes (42 bytes) against a ~429 KB script, and
    makes k >= n, k < 0 and k = 0 all well defined.
    """
    t.push_const(POOL_GROUP_N, curve_n, "_n_red")

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


def emit_ec_mul(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Perform scalar multiplication P * k.

    Stack in: [point, scalar] (scalar on top)
    Stack out: [result_point]

    Uses 256-iteration double-and-add with Jacobian coordinates.
    """
    t = ECTracker(["_pt", "_k"], emit, opts)
    t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
    t.pool_constant(POOL_GROUP_N, EC_CURVE_N)
    # Decompose to affine base point
    _ec_decompose_point(t, "_pt", "ax", "ay")

    # k' = k + 3n: guarantees bit 257 is set.
    # k ∈ [1, n-1], so k+3n ∈ [3n+1, 4n-1]. Since 3n > 2^257, bit 257
    # is always 1. Adding 3n (≡ 0 mod n) preserves the EC point: k*G = (k+3n)*G.
    #
    # "k in [1, n-1]" is a PRECONDITION the caller cannot enforce -- the scalar
    # is usually an unlock argument -- so reduce it first.
    t.to_top("_k")
    _ec_emit_scalar_reduce(t, "_k", "_kr", EC_CURVE_N)
    t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n")
    t.raw_block(["_kr", "_n"], "_kn", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n2")
    t.raw_block(["_kn", "_n2"], "_kn2", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.push_const(POOL_GROUP_N, EC_CURVE_N, "_n3")
    t.raw_block(["_kn2", "_n3"], "_kn3", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.rename("_k")

    # Init accumulator = P (bit 257 of k+3n is always 1)
    t.copy_to_top("ax", "jx")
    t.copy_to_top("ay", "jy")
    t.push_int("jz", 1)

    # 257 iterations: bits 256 down to 0
    for bit in range(256, -1, -1):
        # Double accumulator
        _ec_jacobian_double(t)

        # Extract bit: (k >> bit) & 1, using OP_RSHIFTNUM / OP_2DIV
        t.copy_to_top("_k", "_k_copy")
        if bit == 1:
            # Single-bit shift: OP_2DIV (no push needed)
            t.raw_block(["_k_copy"], "_shifted", lambda e: e(_make_stack_op(op="opcode", code="OP_2DIV")))
        elif bit > 1:
            # Multi-bit shift: push shift amount, OP_RSHIFTNUM
            t.push_int("_shift", bit)
            t.raw_block(["_k_copy", "_shift"], "_shifted", lambda e: e(_make_stack_op(op="opcode", code="OP_RSHIFTNUM")))
        else:
            t.rename("_shifted")
        t.push_int("_two", 2)
        t.raw_block(["_shifted", "_two"], "_bit", lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))

        # Move _bit to TOS and remove from tracker BEFORE generating add ops,
        # because OP_IF consumes _bit and the add ops run with _bit already gone.
        t.to_top("_bit")
        t.pop_tracked()  # _bit consumed by IF
        add_ops: list = []
        add_emit = lambda op: add_ops.append(op)
        # Only the final step can be handed two equal operands -- see
        # _ec_build_jacobian_add_or_double_inline for why, and for what it
        # costs not to.
        if bit == 0:
            _ec_build_jacobian_add_or_double_inline(add_emit, t)
        else:
            _ec_build_jacobian_add_affine_inline(add_emit, t)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

    # Convert Jacobian to affine
    _ec_jacobian_to_affine(t, "_rx", "_ry")

    # Clean up base point and scalar
    t.to_top("ax")
    t.drop()
    t.to_top("ay")
    t.drop()
    t.to_top("_k")
    t.drop()

    # Compose result
    _ec_compose_point(t, "_rx", "_ry", "_result")
    t.release_constant(POOL_GROUP_N)
    t.release_constant(POOL_FIELD_P)


# ===========================================================================
# Fixed-base comb (secp256k1)
# ===========================================================================

def _comb_emit_select(t: ECTracker, i: int, w: int, d: int) -> None:
    """Round *i*'s digit and the selected table entry, as ``ax``/``ay``/``_flag``.

    Exactly one equality holds, so ``sum(eq_j * T_j)`` is that entry's coordinate
    and every term is non-negative and below p -- no reduction is needed, and the
    result is ``REDUCED`` by construction. When the digit is zero every term
    vanishes and ``_flag`` is 0, so no add runs.

    Shared by both comb emitters: the selection is pure scalar bit-twiddling and
    table indexing, with no curve arithmetic in it at all.
    """
    entries = (1 << w) - 1
    for b in range(w):
        shift = i + b * d
        kc, sh = f"_kc{b}", f"_sh{b}"
        t.copy_to_top("_k", kc)
        if shift == 0:
            t.rename(sh)
        elif shift == 1:
            t.raw_block([kc], sh, lambda e: e(_make_stack_op(op="opcode", code="OP_2DIV")))
        else:
            sd = f"_sd{b}"
            t.push_int(sd, shift)
            t.raw_block([kc, sd], sh, lambda e: e(_make_stack_op(op="opcode", code="OP_RSHIFTNUM")))
        two, bit = f"_two{b}", f"_b{b}"
        t.push_int(two, 2)
        t.raw_block([sh, two], bit, lambda e: e(_make_stack_op(op="opcode", code="OP_MOD")))
        t.set_domain(bit, Dom.REDUCED)

    t.to_top("_b0")
    t.rename("_idx")
    for b in range(1, w):
        bit, wt, bw = f"_b{b}", f"_wt{b}", f"_bw{b}"
        t.to_top(bit)
        t.push_int(wt, 1 << b)
        t.raw_block([bit, wt], bw, lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
        t.to_top("_idx")
        t.raw_block([bw, "_idx"], "_idx", lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
    t.set_domain("_idx", Dom.REDUCED)

    for j in range(1, entries + 1):
        ic, jv, eq = f"_ic{j}", f"_jv{j}", f"_eq{j}"
        t.copy_to_top("_idx", ic)
        t.push_int(jv, j)
        t.raw_block([ic, jv], eq, lambda e: e(_make_stack_op(op="opcode", code="OP_NUMEQUAL")))
        t.set_domain(eq, Dom.REDUCED)

    for coord in ("x", "y"):
        acc = "ax" if coord == "x" else "ay"
        for j in range(1, entries + 1):
            ecn, tc, pr = f"_e{coord}{j}", f"_t{coord}{j}", f"_pr{coord}{j}"
            t.copy_to_top(f"_eq{j}", ecn)
            t.copy_to_top(f"_T{coord}{j}", tc)
            t.raw_block([ecn, tc], pr, lambda e: e(_make_stack_op(op="opcode", code="OP_MUL")))
            if j == 1:
                t.rename(acc)
            else:
                t.to_top(acc)
                t.raw_block([pr, acc], acc, lambda e: e(_make_stack_op(op="opcode", code="OP_ADD")))
        t.set_domain(acc, Dom.REDUCED)

    for j in range(entries, 0, -1):
        t.to_top(f"_eq{j}")
        t.drop()

    t.to_top("_idx")
    t.raw_block(["_idx"], "_flag", lambda e: e(_make_stack_op(op="opcode", code="OP_0NOTEQUAL")))


def _ec_emit_comb_mul_gen(emit: Callable, w: int,
                          opts: "EcCodegenOptions | None" = None) -> bool:
    """``k*G`` by a Lim-Lee fixed-base comb instead of the 257-round ladder.

    The ladder doubles and conditionally adds once per SCALAR BIT. A comb splits
    the scalar into ``w`` blocks of ``d`` bits and reads one bit from each block
    per round, so it performs one doubling and one conditional add per COLUMN:
    the round count falls from ``w*d`` to ``d`` at the price of a ``2^w - 1``
    entry table. G is a compile-time constant here, so the table costs nothing to
    build -- ``2*(2^w - 1)`` literal pushes, resident for the whole emitter, read
    by every round with a 2-3 byte ``OP_PICK``.

    This is the secp256k1 twin of ``_c_emit_comb_mul_gen`` in ``p256_p384.py``.
    The curve arithmetic is NOT shared: secp256k1 has ``a = 0``, so
    ``_ec_jacobian_double`` computes ``D = 3X^2`` where the NIST version computes
    ``3(X-Z^2)(X+Z^2)``. Only ``comb.py`` -- the compile-time table and the
    interval checker -- is common, and it takes ``a`` from the curve record.

    SOUNDNESS. The cheap incomplete mixed add cannot represent a pre-add
    accumulator equal to the addend, its negation, or the point at infinity.
    ``_ec_build_jacobian_add_or_double_inline``'s comment justifies using it
    everywhere but the ladder's LAST step by an interval argument over
    ``c_i mod n``, and insists that argument be re-derived by anything changing
    the offset or the iteration count. A comb changes both, so it is re-derived:
    ``comb_safe_rounds`` evaluates the same argument as executable interval
    arithmetic over the comb's own geometry, and any round it cannot prove gets
    the complete add-or-double form instead. Nothing is assumed safe.

    The other half of that argument is that the accumulator never starts at
    infinity, which needs the first digit non-zero. ``comb_geometry`` searches
    for the scalar offset that guarantees it rather than reusing the ladder's
    hardcoded ``+3n`` -- right for secp256k1 at w=3, wrong for P-384.

    Stack in: [_k]. Stack out: [_result]. False when no geometry exists.
    """
    from runar_compiler.codegen.comb import (
        SECP256K1_COMB_CURVE, comb_geometry, comb_safe_rounds, comb_table,
    )

    curve = SECP256K1_COMB_CURVE
    params = comb_geometry(w, curve)
    if params is None:
        return False
    d = params.d
    table = comb_table(w, d, curve)
    safe = comb_safe_rounds(params, curve)
    entries = (1 << w) - 1

    t = ECTracker(["_k"], emit, opts)
    t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
    t.pool_constant(POOL_GROUP_N, EC_CURVE_N)

    # k' = (k mod n) + m*n. The reduce is what confines k to [0, n-1] and so what
    # makes the interval argument apply at all; see _ec_emit_scalar_reduce.
    t.to_top("_k")
    _ec_emit_scalar_reduce(t, "_k", "_kr", EC_CURVE_N)
    t.rename("_k")
    for i in range(params.offset_multiple):
        off = f"_off{i}"
        t.push_const(POOL_GROUP_N, EC_CURVE_N, off)
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
        _ec_jacobian_double(t)
        _comb_emit_select(t, i, w, d)

        # `_ec_jacobian_add_affine_body` documents its layout as
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
            _ec_build_jacobian_add_affine_inline(add_ops.append, t)
        else:
            _ec_build_jacobian_add_or_double_inline(add_ops.append, t)
        emit(_make_stack_op(op="if", then=add_ops, else_=[]))

        # The addend was selected fresh for this round; the add only copied it.
        t.to_top("ay")
        t.drop()
        t.to_top("ax")
        t.drop()

    _ec_jacobian_to_affine(t, "_rx", "_ry")

    for j in range(entries, 0, -1):
        t.to_top(f"_Ty{j}")
        t.drop()
        t.to_top(f"_Tx{j}")
        t.drop()
    t.to_top("_k")
    t.drop()

    _ec_compose_point(t, "_rx", "_ry", "_result")
    t.release_constant(POOL_GROUP_N)
    t.release_constant(POOL_FIELD_P)
    return True


def _ec_emit_comb_best(opts: "EcCodegenOptions | None" = None):
    """Emit the cheapest comb over the candidate window widths.

    Each candidate is rendered in full and scored with the same byte-cost model
    the emitter is measured by, and the smallest wins -- the window width is not
    hardcoded. w=1 is the binary ladder and is excluded; beyond w=4 the ``2^w``
    selection logic outgrows the saving.

    ``None`` when no candidate could be built, so the caller falls back to the
    ladder rather than emitting nothing.
    """
    from runar_compiler.codegen.cost_model import estimate_script_bytes

    best = None
    for w in (2, 3, 4):
        ops: list = []
        if not _ec_emit_comb_mul_gen(ops.append, w, opts):
            continue
        if best is None or estimate_script_bytes(ops) < estimate_script_bytes(best):
            best = ops
    return best


def emit_ec_mul_gen(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Perform scalar multiplication G * k.

    Stack in: [scalar]
    Stack out: [result_point]
    """
    # G is a compile-time constant, so this is the one secp256k1 call site where
    # a fixed-base comb applies. `emit_ec_mul` cannot use it: its base arrives at
    # run time.
    if opts is not None and opts.fixed_base_comb:
        ops = _ec_emit_comb_best(opts)
        if ops is not None:
            for op in ops:
                emit(op)
            return

    # Push generator point as 64-byte blob, then delegate to ecMul
    g_point = _bigint_to_bytes32(EC_GEN_X) + _bigint_to_bytes32(EC_GEN_Y)
    emit(_make_stack_op(op="push", value=_make_push_value(kind="bytes", bytes_=g_point)))
    emit(_make_stack_op(op="swap"))  # [point, scalar]
    emit_ec_mul(emit, opts)


def emit_ec_negate(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Negate a point (x, p - y).

    Stack in: [point]
    Stack out: [negated_point]
    """
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
    _ec_decompose_point(t, "_pt", "_nx", "_ny")
    _ec_push_field_p(t, "_fp")
    _ec_field_sub(t, "_fp", "_ny", "_neg_y")
    _ec_compose_point(t, "_nx", "_neg_y", "_result")
    t.release_constant(POOL_FIELD_P)


def emit_ec_on_curve(emit: Callable, opts: "EcCodegenOptions | None" = None) -> None:
    """Check if point is on secp256k1 (y^2 = x^3 + 7 mod p).

    Stack in: [point]
    Stack out: [boolean]
    """
    t = ECTracker(["_pt"], emit, opts)
    t.pool_constant(POOL_FIELD_P, EC_FIELD_P)
    _ec_decompose_point(t, "_pt", "_x", "_y")

    # GAP-301: coordinate canonicity. ``_ec_decompose_point`` BIN2NUMs each
    # coordinate as an unsigned value that may be >= p; the field arithmetic
    # below would silently reduce it mod p, so a non-canonical encoding of a
    # valid point would pass. Reject it: require x < p AND y < p (coordinates
    # are unsigned, so the 0 <= lower bound holds by construction). Combined
    # with the curve equation at the end via OP_BOOLAND so ecOnCurve still
    # returns a boolean.
    t.copy_to_top("_x", "_x_lt")
    _ec_push_field_p(t, "_p_for_x")
    t.raw_block(["_x_lt", "_p_for_x"], "_x_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.copy_to_top("_y", "_y_lt")
    _ec_push_field_p(t, "_p_for_y")
    t.raw_block(["_y_lt", "_p_for_y"], "_y_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_LESSTHAN")))
    t.to_top("_x_canon")
    t.to_top("_y_canon")
    t.raw_block(["_x_canon", "_y_canon"], "_canon", lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))

    # lhs = y^2
    _ec_field_sqr(t, "_y", "_y2")

    # rhs = x^3 + 7
    t.copy_to_top("_x", "_x_copy")
    _ec_field_sqr(t, "_x", "_x2")
    _ec_field_mul(t, "_x2", "_x_copy", "_x3")
    t.push_int("_seven", 7)
    _ec_field_add(t, "_x3", "_seven", "_rhs")

    # Compare curve equation
    t.to_top("_y2")
    t.to_top("_rhs")
    t.raw_block(["_y2", "_rhs"], "_curve_eq", lambda e: e(_make_stack_op(op="opcode", code="OP_EQUAL")))

    # on-curve = canonical AND curve-equation
    t.to_top("_canon")
    t.to_top("_curve_eq")
    t.raw_block(["_canon", "_curve_eq"], "_result", lambda e: e(_make_stack_op(op="opcode", code="OP_BOOLAND")))
    t.release_constant(POOL_FIELD_P)


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
