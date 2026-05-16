"""
MathDemo -- A stateful contract demonstrating every built-in math function
available in Runar.

Bitcoin Script has limited native arithmetic (ADD, SUB, MUL, DIV, MOD).
Runar provides higher-level math functions that compile into sequences of
these primitives, enabling complex financial calculations on-chain.

Each public method applies one math operation to the contract's stored
``value``, showing how these functions compile to pure Bitcoin Script.
All operations use integer math -- no floating point.

This contract is intentionally minimal: no signature checks are performed,
so any caller can invoke any method. In production, you would combine these
math operations with authentication logic.
"""

from runar import (
    StatefulSmartContract, Bigint, public, assert_,
    safediv, safemod, percent_of, clamp, sign, pow_, sqrt, gcd, mul_div,
    log2, divmod_, abs, min, max, within,
)
from runar.builtins import bool_cast as bool

class MathDemo(StatefulSmartContract):
    """Stateful contract that stores a single mutable ``value`` and exposes
    one public method per built-in math function."""

    value: Bigint

    def __init__(self, value: Bigint):
        super().__init__(value)
        self.value = value

    @public
    def divide_by(self, divisor: Bigint):
        """Safe division -- divides the stored value by ``divisor``, asserting
        that ``divisor`` is non-zero. The transaction fails if divisor is 0.

        Use cases: splitting payments, computing averages.
        """
        self.value = safediv(self.value, divisor)

    @public
    def withdraw_with_fee(self, amount: Bigint, fee_bps: Bigint):
        """Withdraw with a fee calculated in basis points (1 bps = 0.01%).
        ``percent_of(amount, fee_bps)`` computes ``amount * fee_bps / 10000``.
        Asserts that the total (amount + fee) does not exceed the stored value.

        Use cases: fee calculation, royalties, commission deductions.
        """
        fee = percent_of(amount, fee_bps)
        total = amount + fee
        assert_(total <= self.value)
        self.value = self.value - total

    @public
    def clamp_value(self, lo: Bigint, hi: Bigint):
        """Constrains the stored value to the range [lo, hi].
        If value < lo, it becomes lo. If value > hi, it becomes hi.

        Use cases: enforcing min/max limits on bids, prices, or balances.
        """
        self.value = clamp(self.value, lo, hi)

    @public
    def normalize(self):
        """Replaces the stored value with its sign: -1, 0, or 1.

        Use cases: direction detection, comparison results, branch selection.
        """
        self.value = sign(self.value)

    @public
    def exponentiate(self, exp: Bigint):
        """Raises the stored value to the power ``exp`` (integer exponentiation).

        Use cases: compound interest, polynomial evaluation.
        """
        self.value = pow_(self.value, exp)

    @public
    def square_root(self):
        """Replaces the stored value with its integer square root (floor).

        Use cases: geometric mean, distance calculations.
        """
        self.value = sqrt(self.value)

    @public
    def reduce_gcd(self, other: Bigint):
        """Replaces the stored value with gcd(value, other) -- the greatest
        common divisor.

        Use cases: fraction simplification, coprimality checks.
        """
        self.value = gcd(self.value, other)

    @public
    def scale_by_ratio(self, numerator: Bigint, denominator: Bigint):
        """Computes ``(value * numerator) / denominator`` with intermediate
        precision to avoid overflow. Replaces the stored value with the result.

        Use cases: currency conversion, proportional allocation, token swaps.
        """
        self.value = mul_div(self.value, numerator, denominator)

    @public
    def compute_log2(self):
        """Replaces the stored value with floor(log2(value)) -- the floor of
        the base-2 logarithm.

        Use cases: bit-length calculation, binary search depth.
        """
        self.value = log2(self.value)

    @public
    def make_abs(self):
        """Replaces the stored value with its absolute value.

        Use cases: magnitude comparison, distance calculation.
        """
        self.value = abs(self.value)

    @public
    def take_min(self, other: Bigint):
        """Replaces the stored value with min(value, other).

        Use cases: capping bids, picking the smaller of two amounts.
        """
        self.value = min(self.value, other)

    @public
    def take_max(self, other: Bigint):
        """Replaces the stored value with max(value, other).

        Use cases: enforcing reserve floors, picking the larger amount.
        """
        self.value = max(self.value, other)

    @public
    def assert_within(self, lo: Bigint, hi: Bigint):
        """Asserts that the stored value lies in the half-open range
        [lo, hi), mirroring the semantics of Bitcoin Script's OP_WITHIN.

        Use cases: bounds-checked unlock parameters.
        """
        assert_(within(self.value, lo, hi))

    @public
    def modulo_by(self, divisor: Bigint):
        """Safe modulo -- replaces the stored value with ``value mod divisor``,
        asserting that ``divisor`` is non-zero.

        Use cases: round-robin scheduling, modular index calculation.
        """
        self.value = safemod(self.value, divisor)

    @public
    def divmod_by(self, divisor: Bigint):
        """Replaces the stored value with the quotient of
        ``value / divisor`` via Rúnar's ``divmod`` builtin (canonical
        OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP sequence).

        Use cases: integer division with a side-effect on the modulo result.
        """
        self.value = divmod_(self.value, divisor)

    @public
    def assert_non_zero(self):
        """Asserts that the stored value is "truthy" (non-zero) using the
        dedicated ``bool`` builtin which compiles to OP_0NOTEQUAL.

        Use cases: terminal liveness check for non-zero state.
        """
        assert_(bool(self.value))
