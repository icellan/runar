pragma runar ^0.1.0;

/// @title MerkleProofDemo
/// @notice Demonstrates Merkle proof verification in Bitcoin Script.
/// @dev Two built-in functions:
/// - merkleRootSha256(leaf, proof, index, depth) — SHA-256 Merkle root (STARK/FRI)
/// - merkleRootHash256(leaf, proof, index, depth) — Hash256 Merkle root (Bitcoin)
///
/// Parameters:
/// - leaf: 32-byte leaf hash
/// - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
/// - index: leaf position (determines left/right at each level)
/// - depth: number of tree levels (MUST be a compile-time constant)
///
/// The depth parameter is consumed at compile time — the loop is unrolled,
/// producing ~15 opcodes per level. No runtime iteration.
contract MerkleProofDemo is SmartContract {
    ByteString immutable expectedRoot;

    constructor(ByteString _expectedRoot) {
        expectedRoot = _expectedRoot;
    }

    /// @notice Verify a SHA-256 Merkle proof at depth 4.
    /// @param leaf The 32-byte leaf hash
    /// @param proof Concatenated sibling hashes (4 * 32 = 128 bytes)
    /// @param index Leaf position in the tree
    function verifySha256(ByteString leaf, ByteString proof, bigint index) public {
        ByteString root = merkleRootSha256(leaf, proof, index, 4);
        require(root == this.expectedRoot);
    }

    /// @notice Verify a Hash256 Merkle proof at depth 4.
    /// @param leaf The 32-byte leaf hash
    /// @param proof Concatenated sibling hashes (4 * 32 = 128 bytes)
    /// @param index Leaf position in the tree
    function verifyHash256(ByteString leaf, ByteString proof, bigint index) public {
        ByteString root = merkleRootHash256(leaf, proof, index, 4);
        require(root == this.expectedRoot);
    }
}
