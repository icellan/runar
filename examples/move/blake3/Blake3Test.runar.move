// Blake3Test — A stateless contract demonstrating BLAKE3 hash primitives
// in Runar.
//
// BLAKE3 is a cryptographic hash function that is significantly faster
// than SHA-256 while maintaining strong security guarantees. Runar provides
// two BLAKE3 built-in functions that compile into inlined Bitcoin Script
// opcodes for on-chain hash verification.
//
// BLAKE3 internals:
//   - Uses a Merkle tree structure built from 64-byte blocks
//   - Each block is processed by the BLAKE3 compression function
//   - The compression function mixes a 32-byte chaining value with a 64-byte
//     block using 7 rounds of the BLAKE3 G mixing function
//   - The standard IV (initialization vector) is:
//     6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
//     (same as the first 8 words of SHA-256's IV, derived from sqrt(2..9))
//
// The 2 BLAKE3 primitives:
//   blake3Compress(chainingValue, block) — single-block compression
//   blake3Hash(message) — full hash for messages up to 64 bytes
//
// blake3Compress takes a 32-byte chaining value and a 64-byte block,
// returning the 32-byte compressed output. This is the core building block
// for constructing custom BLAKE3 Merkle trees on-chain.
//
// blake3Hash computes the full BLAKE3 hash of a message (up to 64 bytes),
// handling IV initialization, padding, and domain flags internally. This is
// the simplest way to verify a BLAKE3 hash on-chain.
//
// This contract is stateless (SmartContract), so each method is an
// independent spending condition. No signature checks are performed.
module Blake3Test {
    use runar::types::{ByteString};
    use runar::crypto::{blake3Compress, blake3Hash};

    struct Blake3Test {
        // The expected hash output (32 bytes).
        // Set at deployment time; each spending method verifies its computed
        // result against this value.
        expected: ByteString,
    }

    // Verify a single BLAKE3 compression invocation.
    // Compresses a 64-byte block using the given 32-byte chaining value
    // and asserts the result matches the stored expected hash. This is useful
    // for verifying individual nodes in a BLAKE3 Merkle tree.
    public fun verify_compress(contract: &Blake3Test, chaining_value: ByteString, block: ByteString) {
        let result: ByteString = blake3Compress(chaining_value, block);
        assert!(result == contract.expected, 0);
    }

    // Verify a full BLAKE3 hash of a message.
    // Computes blake3Hash(message) and asserts the result matches the
    // stored expected hash. The message must be at most 64 bytes. This is the
    // simplest on-chain BLAKE3 verification: deploy with the expected digest,
    // then spend by providing the preimage.
    public fun verify_hash(contract: &Blake3Test, message: ByteString) {
        let result: ByteString = blake3Hash(message);
        assert!(result == contract.expected, 0);
    }
}
