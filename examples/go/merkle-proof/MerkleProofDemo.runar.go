package contract

import runar "github.com/icellan/runar/packages/runar-go"

// MerkleProofDemo demonstrates Merkle proof verification in Bitcoin Script.
//
// Two built-in functions:
//   - MerkleRootSha256(leaf, proof, index, depth) — SHA-256 Merkle root (STARK/FRI)
//   - MerkleRootHash256(leaf, proof, index, depth) — Hash256 Merkle root (Bitcoin)
//
// Parameters:
//   - leaf: 32-byte leaf hash
//   - proof: concatenated 32-byte sibling hashes (depth * 32 bytes)
//   - index: leaf position (determines left/right at each level)
//   - depth: number of tree levels (MUST be a compile-time constant)
//
// The depth parameter is consumed at compile time — the loop is unrolled,
// producing ~15 opcodes per level. No runtime iteration.
type MerkleProofDemo struct {
	runar.SmartContract
	ExpectedRoot runar.ByteString `runar:"readonly"`
}

// VerifySha256 verifies a SHA-256 Merkle proof at depth 4.
func (c *MerkleProofDemo) VerifySha256(leaf, proof runar.ByteString, index runar.Bigint) {
	root := runar.MerkleRootSha256(leaf, proof, index, 4)
	runar.Assert(root == c.ExpectedRoot)
}

// VerifyHash256 verifies a Hash256 Merkle proof at depth 4.
func (c *MerkleProofDemo) VerifyHash256(leaf, proof runar.ByteString, index runar.Bigint) {
	root := runar.MerkleRootHash256(leaf, proof, index, 4)
	runar.Assert(root == c.ExpectedRoot)
}
