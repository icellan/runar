pragma runar ^0.1.0;

/// P384EncodeNegate — Solidity-like port. Executed coverage for p384Negate and
/// p384EncodeCompressed, neither of which appeared in any fixture.
/// See the `.runar.ts` port for the full rationale.
contract P384EncodeNegate is SmartContract {
    ByteString immutable expectedCompressed;

    constructor(ByteString _expectedCompressed) {
        expectedCompressed = _expectedCompressed;
    }

    /// (x, y) -> (x, p - y). Guards coordinate canonicity AND the 96-byte width.
    function checkNegate(P384Point p, P384Point expected) public {
        P384Point n = p384Negate(p);
        require(n == expected);
    }

    /// Point -> 49-byte 02/03||x. Guards the width; parity read at a fixed offset.
    function checkEncode(P384Point p, ByteString expected) public {
        ByteString e = p384EncodeCompressed(p);
        require(e == expected);
    }

    /// Composed: compressing the negation must flip the prefix and nothing else.
    function checkNegateThenEncode(P384Point p) public {
        P384Point n = p384Negate(p);
        ByteString e = p384EncodeCompressed(n);
        require(e == this.expectedCompressed);
    }
}
