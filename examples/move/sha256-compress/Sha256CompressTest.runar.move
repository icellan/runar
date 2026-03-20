module Sha256CompressTest {
    use runar::types::{ByteString};
    use runar::crypto::{sha256Compress};

    /// Sha256CompressTest — verifies SHA-256 compression correctness on-chain.
    ///
    /// sha256Compress performs one round of SHA-256 block compression (FIPS 180-4
    /// Section 6.2.2). Takes a 32-byte state and 64-byte block, returns 32-byte state.
    struct Sha256CompressTest {
        expected: ByteString,
    }

    public fun verify(contract: &Sha256CompressTest, state: ByteString, block: ByteString) {
        let result: ByteString = sha256Compress(state, block);
        assert!(result == contract.expected, 0);
    }
}
