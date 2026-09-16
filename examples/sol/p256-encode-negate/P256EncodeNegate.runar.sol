pragma runar ^0.1.0;

/// P256EncodeNegate — Solidity-like port. Executed coverage for p256Negate and
/// p256EncodeCompressed, neither of which appeared in any fixture.
/// See the `.runar.ts` port for the full rationale.
contract P256EncodeNegate is SmartContract {
    ByteString immutable expectedCompressed;

    constructor(ByteString _expectedCompressed) {
        expectedCompressed = _expectedCompressed;
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 64-byte width.
    function checkNegate(P256Point p, P256Point expected) public {
        P256Point n = p256Negate(p);
        require(n == expected);
    }

    /// Point -> 33-byte 02/03||x. Guards the width; parity read at a fixed offset.
    function checkEncode(P256Point p, ByteString expected) public {
        ByteString e = p256EncodeCompressed(p);
        require(e == expected);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    function checkNegateThenEncode(P256Point p) public {
        P256Point n = p256Negate(p);
        ByteString e = p256EncodeCompressed(n);
        require(e == this.expectedCompressed);
    }
}
