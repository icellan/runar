use runar::prelude::*;

/// MerkleProofDemo -- Demonstrates Merkle proof verification in Bitcoin Script.
///
/// Two built-in functions:
/// - `merkle_root_sha256(leaf, proof, index, depth)` -- SHA-256 Merkle root (STARK/FRI)
/// - `merkle_root_hash256(leaf, proof, index, depth)` -- Hash256 Merkle root (Bitcoin)
///
/// Parameters:
/// - leaf: 32-byte leaf hash
/// - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
/// - index: leaf position (determines left/right at each level)
/// - depth: number of tree levels (MUST be a compile-time constant)
///
/// The depth parameter is consumed at compile time -- the loop is unrolled,
/// producing ~15 opcodes per level. No runtime iteration.
#[runar::contract]
pub struct MerkleProofDemo {
    #[readonly]
    pub expected_root: ByteString,
}

#[runar::methods(MerkleProofDemo)]
impl MerkleProofDemo {
    /// Verify a SHA-256 Merkle proof at depth 4.
    #[public]
    pub fn verify_sha256(&self, leaf: ByteString, proof: ByteString, index: Bigint) {
        let root = merkle_root_sha256(&leaf, &proof, index, 4);
        assert!(root == self.expected_root);
    }

    /// Verify a Hash256 Merkle proof at depth 4.
    #[public]
    pub fn verify_hash256(&self, leaf: ByteString, proof: ByteString, index: Bigint) {
        let root = merkle_root_hash256(&leaf, &proof, index, 4);
        assert!(root == self.expected_root);
    }
}
