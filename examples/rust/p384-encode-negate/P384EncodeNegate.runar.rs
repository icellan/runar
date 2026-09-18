use runar::prelude::*;

/// P384EncodeNegate -- Rust DSL port. Executed coverage for p384_negate and
/// p384_encode_compressed, neither of which appeared in any fixture.
/// See the `.runar.ts` port for the full rationale.
#[runar::contract]
struct P384EncodeNegate {
    #[readonly]
    expected_compressed: ByteString,
}

impl P384EncodeNegate {
    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 96-byte width.
    pub fn check_negate(&self, p: &P384Point, expected: &P384Point) {
        let n = p384_negate(p);
        assert!(n == expected);
    }

    /// Point -> 49-byte 02/03||x. Guards the width; parity read at a fixed offset.
    pub fn check_encode(&self, p: &P384Point, expected: &ByteString) {
        let e = p384_encode_compressed(p);
        assert!(e == expected);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    pub fn check_negate_then_encode(&self, p: &P384Point) {
        let n = p384_negate(p);
        let e = p384_encode_compressed(&n);
        assert!(e == self.expected_compressed);
    }
}
