// P384EncodeNegate -- Move-style port. Executed coverage for p384_negate and
// p384_encode_compressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
module P384EncodeNegate {
    use runar::types::{P384Point, ByteString};
    use runar::crypto::{p384_negate, p384_encode_compressed};

    struct P384EncodeNegate {
        expected_compressed: ByteString,
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 96-byte width.
    public fun check_negate(contract: &P384EncodeNegate, p: P384Point, expected: P384Point) {
        let n: P384Point = p384_negate(p);
        assert!(n == expected, 0);
    }

    /// Point -> 49-byte 02/03||x. Guards the width; parity read at a fixed offset.
    public fun check_encode(contract: &P384EncodeNegate, p: P384Point, expected: ByteString) {
        let e: ByteString = p384_encode_compressed(p);
        assert!(e == expected, 0);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    public fun check_negate_then_encode(contract: &P384EncodeNegate, p: P384Point) {
        let n: P384Point = p384_negate(p);
        let e: ByteString = p384_encode_compressed(n);
        assert!(e == contract.expected_compressed, 0);
    }
}
