"""P384EncodeNegate -- Python port. Executed coverage for p384_negate and
p384_encode_compressed, neither of which appeared in any fixture.
See the `.runar.ts` port for the full rationale.
"""

from runar import SmartContract, ByteString, public, assert_, p384_negate, p384_encode_compressed


class P384EncodeNegate(SmartContract):
    expected_compressed: ByteString

    def __init__(self, expected_compressed: ByteString):
        super().__init__(expected_compressed)
        self.expected_compressed = expected_compressed

    @public
    def check_negate(self, p: P384Point, expected: P384Point):
        """(x, y) -> (x, p - y). Guards canonicity AND the 96-byte width."""
        n = p384_negate(p)
        assert_(n == expected)

    @public
    def check_encode(self, p: P384Point, expected: ByteString):
        """Point -> 49-byte 02/03||x, parity read at a fixed offset."""
        e = p384_encode_compressed(p)
        assert_(e == expected)

    @public
    def check_negate_then_encode(self, p: P384Point):
        """Composed: compressing the negation must flip the prefix only."""
        n = p384_negate(p)
        e = p384_encode_compressed(n)
        assert_(e == self.expected_compressed)
