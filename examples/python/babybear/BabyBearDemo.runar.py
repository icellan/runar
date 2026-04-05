"""BabyBearDemo -- Demonstrates Baby Bear prime field arithmetic.

Baby Bear is the prime field used by SP1 STARK proofs (FRI verification).
Field prime: p = 2^31 - 2^27 + 1 = 2013265921

Four operations:
  - bb_field_add(a, b) -- (a + b) mod p
  - bb_field_sub(a, b) -- (a - b + p) mod p
  - bb_field_mul(a, b) -- (a * b) mod p
  - bb_field_inv(a) -- a^(p-2) mod p (multiplicative inverse via Fermat)
"""

from runar import (
    SmartContract, Bigint, public, assert_,
    bb_field_add, bb_field_sub, bb_field_mul, bb_field_inv,
)


class BabyBearDemo(SmartContract):
    """Demonstrates Baby Bear prime field arithmetic."""

    def __init__(self):
        super().__init__()

    @public
    def check_add(self, a: Bigint, b: Bigint, expected: Bigint):
        """Verify field addition."""
        assert_(bb_field_add(a, b) == expected)

    @public
    def check_sub(self, a: Bigint, b: Bigint, expected: Bigint):
        """Verify field subtraction."""
        assert_(bb_field_sub(a, b) == expected)

    @public
    def check_mul(self, a: Bigint, b: Bigint, expected: Bigint):
        """Verify field multiplication."""
        assert_(bb_field_mul(a, b) == expected)

    @public
    def check_inv(self, a: Bigint):
        """Verify field inversion: a * inv(a) === 1."""
        inv = bb_field_inv(a)
        assert_(bb_field_mul(a, inv) == 1)

    @public
    def check_add_sub_roundtrip(self, a: Bigint, b: Bigint):
        """Verify subtraction is the inverse of addition: (a + b) - b === a."""
        sum_ = bb_field_add(a, b)
        result = bb_field_sub(sum_, b)
        assert_(result == a)

    @public
    def check_distributive(self, a: Bigint, b: Bigint, c: Bigint):
        """Verify distributive law: a * (b + c) === a*b + a*c."""
        lhs = bb_field_mul(a, bb_field_add(b, c))
        rhs = bb_field_add(bb_field_mul(a, b), bb_field_mul(a, c))
        assert_(lhs == rhs)
