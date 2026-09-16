use runar::prelude::*;

/// P256EncodeNegate -- Rust DSL port. Executed coverage for p256_negate and
/// p256_encode_compressed, neither of which appeared in any fixture.
/// See the `.runar.ts` port for the full rationale.
#[runar::contract]
struct P256EncodeNegate {
    #[readonly]
    expected_compressed: ByteString,
}

impl P256EncodeNegate {
    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width.
    pub fn check_negate(&self, p: &P256Point, expected: &P256Point) {
        let n = p256_negate(p);
        assert!(n == expected);
    }

    /// Point -> 33-byte 02/03||x. Guards the width; parity read at a fixed offset.
    pub fn check_encode(&self, p: &P256Point, expected: &ByteString) {
        let e = p256_encode_compressed(p);
        assert!(e == expected);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    pub fn check_negate_then_encode(&self, p: &P256Point) {
        let n = p256_negate(p);
        let e = p256_encode_compressed(&n);
        assert!(e == self.expected_compressed);
    }
}
