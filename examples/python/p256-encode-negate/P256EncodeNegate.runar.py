"""P256EncodeNegate -- Python port. Executed coverage for p256_negate and
p256_encode_compressed, neither of which appeared in any fixture.
See the `.runar.ts` port for the full rationale.
"""

from runar import SmartContract, ByteString, public, assert_, p256_negate, p256_encode_compressed


class P256EncodeNegate(SmartContract):
    expected_compressed: ByteString

    def __init__(self, expected_compressed: ByteString):
        super().__init__(expected_compressed)
        self.expected_compressed = expected_compressed

    @public
    def check_negate(self, p: P256Point, expected: P256Point):
        """(x, y) -> (x, p - y). Guards canonicity AND the 64-byte width."""
        n = p256_negate(p)
        assert_(n == expected)

    @public
    def check_encode(self, p: P256Point, expected: ByteString):
        """Point -> 33-byte 02/03||x, parity read at a fixed offset."""
        e = p256_encode_compressed(p)
        assert_(e == expected)

    @public
    def check_negate_then_encode(self, p: P256Point):
        """Composed: compressing the negation must flip the prefix only."""
        n = p256_negate(p)
        e = p256_encode_compressed(n)
        assert_(e == self.expected_compressed)
