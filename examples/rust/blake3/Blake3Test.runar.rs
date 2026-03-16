use runar::prelude::*;

/// Blake3Test -- A stateless contract demonstrating the built-in BLAKE3 hash
/// primitives available in Runar.
///
/// **What is BLAKE3?**
/// BLAKE3 is a modern cryptographic hash function published in 2020, designed as
/// the successor to BLAKE2. It is based on the Bao tree hashing mode and uses a
/// compression function derived from BLAKE2s with reduced rounds (7 instead of
/// 10). BLAKE3 produces a 256-bit (32-byte) digest and is designed for speed,
/// security, and parallelism. Its compression function operates on a 16-word
/// (64-byte) internal state using a series of quarter-round "G" mixing calls.
///
/// **How BLAKE3 compression works (`blake3_compress`):**
/// The core primitive is a single compression function invocation. It takes:
/// - A 32-byte chaining value (8 x 32-bit words)
/// - A 64-byte message block (16 x 32-bit words)
///
/// The compression initializes a 16-word state from the chaining value, the
/// BLAKE3 initialization vector (IV), a counter (hardcoded to 0), the block
/// length, and domain separation flags. It then runs 7 rounds, each consisting
/// of 8 quarter-round G function calls (4 column mixing + 4 diagonal mixing).
/// Between rounds, the message words are permuted. The final output XORs the
/// first 8 state words with the last 8 to produce the 32-byte hash.
///
/// The G function performs:
/// ```text
/// a = a + b + mx
/// d = (d ^ a) >>> 16
/// c = c + d
/// b = (b ^ c) >>> 12
/// a = a + b + my
/// d = (d ^ a) >>> 8
/// c = c + d
/// b = (b ^ c) >>> 7
/// ```
///
/// The compiled Bitcoin Script for `blake3_compress` is approximately 10,000
/// opcodes (~11 KB), making it practical for on-chain hash verification.
///
/// **How `blake3_hash` works:**
/// `blake3_hash(message)` is a convenience wrapper for single-block hashing. It
/// zero-pads the message to 64 bytes and calls the compression function with
/// the BLAKE3 IV as the chaining value. The hardcoded parameters are:
/// - blockLen = 64 (full block, even if the message is shorter)
/// - flags = 11 (CHUNK_START | CHUNK_END | ROOT)
/// - counter = 0
///
/// **BLAKE3 IV (big-endian hex):**
/// `6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`
/// (These are the same fractional-part constants used by SHA-256.)
///
/// **Use cases:**
/// - Proof-of-work verification: verify that a preimage hashes to a target
/// - Hash-locked payments: lock funds to a BLAKE3 preimage (alternative to SHA-256)
/// - Commitment schemes: commit to a value with BLAKE3, reveal later
/// - Data integrity: verify that on-chain data matches an expected digest
/// - Hybrid hash protocols: combine BLAKE3 with SHA-256 for defense in depth
#[runar::contract]
pub struct Blake3Test {
    /// The expected 32-byte BLAKE3 digest. Set at deployment time as part of
    /// the locking script. Each spending method computes a BLAKE3 hash from
    /// unlocking arguments and asserts it matches this value.
    #[readonly]
    pub expected: ByteString,
}

#[runar::methods(Blake3Test)]
impl Blake3Test {
    /// Verify a BLAKE3 compression function invocation.
    ///
    /// Computes `blake3_compress(chaining_value, block)` and asserts the
    /// 32-byte result matches `self.expected`. This is the raw compression
    /// primitive -- the caller provides both the chaining value and the
    /// full 64-byte block.
    ///
    /// The compression uses hardcoded parameters:
    /// - counter = 0 (first and only chunk)
    /// - blockLen = 64 (full block)
    /// - flags = 11 (CHUNK_START | CHUNK_END | ROOT)
    ///
    /// Use this method when you need full control over the chaining value,
    /// for example when verifying intermediate nodes in a BLAKE3 Merkle tree
    /// or when implementing multi-block BLAKE3 hashing with custom chaining.
    #[public]
    pub fn verify_compress(&self, chaining_value: &ByteString, block: &ByteString) {
        let result = blake3_compress(chaining_value, block);
        assert!(result == self.expected);
    }

    /// Verify a BLAKE3 hash of a message up to 64 bytes.
    ///
    /// Computes `blake3_hash(message)` and asserts the 32-byte result
    /// matches `self.expected`. This is the high-level convenience function --
    /// it automatically zero-pads the message to 64 bytes and uses the
    /// BLAKE3 IV as the chaining value.
    ///
    /// This is the simplest way to verify a BLAKE3 hash on-chain. The
    /// spender provides the preimage (message) and the script verifies it
    /// hashes to the expected digest baked into the locking script.
    ///
    /// Note: blockLen is hardcoded to 64 in the compiled script regardless
    /// of the actual message length. For interoperability with off-chain
    /// BLAKE3 libraries, use `blake3_compress` directly with the correct
    /// blockLen encoding.
    #[public]
    pub fn verify_hash(&self, message: &ByteString) {
        let result = blake3_hash(message);
        assert!(result == self.expected);
    }
}
