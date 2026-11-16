"""TernaryExpression -- see TernaryExpression.runar.ts."""

from runar import SmartContract, ByteString, Bigint, public, assert_


class TernaryExpression(SmartContract):
    threshold: Bigint
    high_tag: ByteString
    low_tag: ByteString

    def __init__(self, threshold: Bigint, high_tag: ByteString, low_tag: ByteString):
        super().__init__(threshold, high_tag, low_tag)
        self.threshold = threshold
        self.high_tag = high_tag
        self.low_tag = low_tag

    @public
    def check(self, x: Bigint, distance: Bigint, tag: ByteString, band: Bigint):
        d = x - self.threshold if x > self.threshold else self.threshold - x
        assert_(d == distance)

        t = self.high_tag if x > self.threshold else self.low_tag
        assert_(t == tag)

        b = 2 if x > self.threshold else (1 if x == self.threshold else 0)
        assert_(b == band)
