"""ShiftOps -- Exercises bitshift operators ``<<`` and ``>>`` on Bigint values."""

from runar import SmartContract, Bigint, public, assert_


class ShiftOps(SmartContract):
    """Exercises bitshift operators on Bigint values."""

    a: Bigint

    def __init__(self, a: Bigint):
        super().__init__(a)
        self.a = a

    @public
    def test_shift(self, expected_left: Bigint, expected_right: Bigint):
        """Apply left shift and right shift, then check the caller-supplied results."""
        left = self.a << 3
        right = self.a >> 2
        assert_(left == expected_left)
        assert_(right == expected_right)
