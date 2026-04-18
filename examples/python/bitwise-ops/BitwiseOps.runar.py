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
    def test_shift(self):
        """Verify shift operators compile and run."""
        left = self.a << 2
        right = self.a >> 1
        assert_(left >= 0 or left < 0)
        assert_(right >= 0 or right < 0)
        assert_(True)

    @public
    def test_bitwise(self):
        """Verify bitwise operators compile and run."""
        and_result = self.a & self.b
        or_result = self.a | self.b
        xor_result = self.a ^ self.b
        not_result = ~self.a
        assert_(and_result >= 0 or and_result < 0)
        assert_(or_result >= 0 or or_result < 0)
        assert_(xor_result >= 0 or xor_result < 0)
        assert_(not_result >= 0 or not_result < 0)
        assert_(True)
