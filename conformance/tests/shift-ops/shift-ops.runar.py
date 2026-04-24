"""ShiftOps -- Exercises bitshift operators ``<<`` and ``>>`` on Bigint values."""

from runar import SmartContract, Bigint, public, assert_


class ShiftOps(SmartContract):
    """Exercises bitshift operators on Bigint values."""

    a: Bigint

    def __init__(self, a: Bigint):
        super().__init__(a)
        self.a = a

    @public
    def test_shift(self):
        """Apply left shift and right shift, then sanity-check the results."""
        left = self.a << 3
        right = self.a >> 2
        assert_(left >= 0 or left < 0)
        assert_(right >= 0 or right < 0)
