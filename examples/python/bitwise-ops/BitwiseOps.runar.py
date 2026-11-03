"""BitwiseOps -- Demonstrates bitwise and shift operators on Bigint values."""

from runar import SmartContract, Bigint, public, assert_


class BitwiseOps(SmartContract):
    """Demonstrates bitwise and shift operators."""

    a: Bigint
    b: Bigint

    def __init__(self, a: Bigint, b: Bigint):
        super().__init__(a, b)
        self.a = a
        self.b = b

    @public
    def test_shift(self, expected_left: Bigint, expected_right: Bigint):
        """Check the caller-supplied shift results."""
        left = self.a << 2
        right = self.a >> 1
        assert_(left == expected_left)
        assert_(right == expected_right)

    @public
    def test_bitwise(self, expected_and: Bigint, expected_or: Bigint, expected_xor: Bigint):
        """Check the caller-supplied AND/OR/XOR results; ``~`` is checked by
        double inversion and De Morgan's law (see the TS source for why)."""
        and_result = self.a & self.b
        or_result = self.a | self.b
        xor_result = self.a ^ self.b
        not_result = ~self.a
        assert_(and_result == expected_and)
        assert_(or_result == expected_or)
        assert_(xor_result == expected_xor)
        assert_(~not_result == self.a)
        assert_(~(self.a | self.b) == (not_result & ~self.b))
