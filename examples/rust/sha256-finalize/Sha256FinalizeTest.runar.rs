use runar::prelude::*;

/// Sha256FinalizeTest -- verifies SHA-256 finalize correctness on-chain.
///
/// The sha256_finalize intrinsic handles FIPS 180-4 padding internally: it
/// appends the 0x80 byte, zero-pads, and appends the 8-byte big-endian bit
/// length, then compresses one or two blocks depending on the remaining length.
///
/// - remaining <= 55 bytes: single-block path (one compression)
/// - 56-119 bytes: two-block path (two compressions)
///
/// The msg_bit_len parameter is the TOTAL message bit length (across all prior
/// compress calls), used in the final padding suffix.
#[runar::contract]
pub struct Sha256FinalizeTest {
    #[readonly]
    pub expected: ByteString,
}

#[runar::methods(Sha256FinalizeTest)]
impl Sha256FinalizeTest {
    #[public]
    pub fn verify(&self, state: &ByteString, remaining: &ByteString, msg_bit_len: Bigint) {
        let result = sha256_finalize(state, remaining, msg_bit_len);
        assert!(result == self.expected);
    }
}
