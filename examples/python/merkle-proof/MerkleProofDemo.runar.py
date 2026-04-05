"""MerkleProofDemo -- Demonstrates Merkle proof verification in Bitcoin Script.

Two built-in functions:
  - merkle_root_sha256(leaf, proof, index, depth) -- SHA-256 Merkle root (STARK/FRI)
  - merkle_root_hash256(leaf, proof, index, depth) -- Hash256 Merkle root (Bitcoin)

Parameters:
  - leaf: 32-byte leaf hash
  - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
  - index: leaf position (determines left/right at each level)
  - depth: number of tree levels (MUST be a compile-time constant)

The depth parameter is consumed at compile time -- the loop is unrolled,
producing ~15 opcodes per level. No runtime iteration.
"""

from runar import (
    SmartContract, ByteString, Bigint, public, assert_,
    merkle_root_sha256, merkle_root_hash256,
)


class MerkleProofDemo(SmartContract):
    """Demonstrates Merkle proof verification."""

    expected_root: ByteString

    def __init__(self, expected_root: ByteString):
        super().__init__(expected_root)
        self.expected_root = expected_root

    @public
    def verify_sha256(self, leaf: ByteString, proof: ByteString, index: Bigint):
        """Verify a SHA-256 Merkle proof at depth 4."""
        root = merkle_root_sha256(leaf, proof, index, 4)
        assert_(root == self.expected_root)

    @public
    def verify_hash256(self, leaf: ByteString, proof: ByteString, index: Bigint):
        """Verify a Hash256 Merkle proof at depth 4."""
        root = merkle_root_hash256(leaf, proof, index, 4)
        assert_(root == self.expected_root)
