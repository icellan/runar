module Sha256FinalizeTest {
    use runar::types::{ByteString};
    use runar::crypto::{sha256Finalize};

    /// Sha256FinalizeTest — verifies SHA-256 finalize correctness on-chain.
    ///
    /// sha256Finalize handles FIPS 180-4 padding internally and branches between
    /// single-block (remaining <= 55 bytes) and two-block (56-119 bytes) paths.
    struct Sha256FinalizeTest {
        expected: ByteString,
    }

    public fun verify(contract: &Sha256FinalizeTest, state: ByteString, remaining: ByteString, msg_bit_len: u64) {
        let result: ByteString = sha256Finalize(state, remaining, msg_bit_len);
        assert!(result == contract.expected, 0);
    }
}
