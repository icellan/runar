pragma runar ^0.1.0;

/// Sha256FinalizeTest — verifies SHA-256 finalize correctness on-chain.
///
/// sha256Finalize handles FIPS 180-4 padding internally and branches between
/// single-block (remaining <= 55 bytes) and two-block (56-119 bytes) paths.
contract Sha256FinalizeTest is SmartContract {
    ByteString immutable expected;

    constructor(ByteString _expected) {
        expected = _expected;
    }

    function verify(ByteString state, ByteString remaining, int msgBitLen) public {
        ByteString result = sha256Finalize(state, remaining, msgBitLen);
        require(result == this.expected);
    }
}
