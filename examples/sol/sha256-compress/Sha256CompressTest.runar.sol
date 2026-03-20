pragma runar ^0.1.0;

/// Sha256CompressTest — verifies SHA-256 compression correctness on-chain.
///
/// sha256Compress performs one round of SHA-256 block compression (FIPS 180-4
/// Section 6.2.2). Takes a 32-byte state and 64-byte block, returns 32-byte state.
contract Sha256CompressTest is SmartContract {
    ByteString immutable expected;

    constructor(ByteString _expected) {
        expected = _expected;
    }

    function verify(ByteString state, ByteString block) public {
        ByteString result = sha256Compress(state, block);
        require(result == this.expected);
    }
}
