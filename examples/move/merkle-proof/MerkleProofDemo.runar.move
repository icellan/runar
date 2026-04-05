// MerkleProofDemo — Demonstrates Merkle proof verification in Bitcoin Script.
//
// Two built-in functions:
// - merkleRootSha256(leaf, proof, index, depth) — SHA-256 Merkle root (STARK/FRI)
// - merkleRootHash256(leaf, proof, index, depth) — Hash256 Merkle root (Bitcoin)
//
// Parameters:
// - leaf: 32-byte leaf hash
// - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
// - index: leaf position (determines left/right at each level)
// - depth: number of tree levels (MUST be a compile-time constant)
//
// The depth parameter is consumed at compile time — the loop is unrolled,
// producing ~15 opcodes per level. No runtime iteration.
module MerkleProofDemo {
    use runar::types::{ByteString};
    use runar::crypto::{merkleRootSha256, merkleRootHash256};

    struct MerkleProofDemo {
        expected_root: ByteString,
    }

    // Verify a SHA-256 Merkle proof at depth 4.
    public fun verify_sha256(contract: &MerkleProofDemo, leaf: ByteString, proof: ByteString, index: bigint) {
        let root: ByteString = merkleRootSha256(leaf, proof, index, 4);
        assert!(root == contract.expected_root, 0);
    }

    // Verify a Hash256 Merkle proof at depth 4.
    public fun verify_hash256(contract: &MerkleProofDemo, leaf: ByteString, proof: ByteString, index: bigint) {
        let root: ByteString = merkleRootHash256(leaf, proof, index, 4);
        assert!(root == contract.expected_root, 0);
    }
}
