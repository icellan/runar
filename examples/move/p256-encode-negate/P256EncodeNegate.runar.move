// P256EncodeNegate -- Move-style port. Executed coverage for p256_negate and
// p256_encode_compressed, neither of which appeared in any fixture.
// See the `.runar.ts` port for the full rationale.
module P256EncodeNegate {
    use runar::types::{P256Point, ByteString};
    use runar::crypto::{p256_negate, p256_encode_compressed};

    struct P256EncodeNegate {
        expected_compressed: ByteString,
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width.
    public fun check_negate(contract: &P256EncodeNegate, p: P256Point, expected: P256Point) {
        let n: P256Point = p256_negate(p);
        assert!(n == expected, 0);
    }

    /// Point -> 33-byte 02/03||x. Guards the width; parity read at a fixed offset.
    public fun check_encode(contract: &P256EncodeNegate, p: P256Point, expected: ByteString) {
        let e: ByteString = p256_encode_compressed(p);
        assert!(e == expected, 0);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    public fun check_negate_then_encode(contract: &P256EncodeNegate, p: P256Point) {
        let n: P256Point = p256_negate(p);
        let e: ByteString = p256_encode_compressed(n);
        assert!(e == contract.expected_compressed, 0);
    }
}
