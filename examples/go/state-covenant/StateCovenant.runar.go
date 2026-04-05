package contract

import runar "github.com/icellan/runar/packages/runar-go"

// StateCovenant — a stateful UTXO chain covenant that guards a state root.
//
// Demonstrates the core pattern for a validity-proof-based state covenant:
// each spend advances the state by providing a new state root, a block number,
// and proof data. The covenant verifies the proof and enforces monotonic
// block number progression.
//
// This contract exercises the key primitives needed for STARK/FRI verification
// on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof verification, and
// hash256 batch data binding — without implementing the full FRI verifier.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - StateRoot: 32-byte hash representing the current state
//   - BlockNumber: monotonically increasing block counter
//
// Readonly property (baked into locking script at compile time):
//   - VerifyingKeyHash: commitment to the proof system's verifying key;
//     also used as the expected Merkle root for commitment verification
type StateCovenant struct {
	runar.StatefulSmartContract
	StateRoot        runar.ByteString                // mutable state
	BlockNumber      runar.Bigint                    // mutable state
	VerifyingKeyHash runar.ByteString `runar:"readonly"` // compile-time constant
}

// AdvanceState advances the covenant state. Verifies proof data and updates
// state root and block number.
func (c *StateCovenant) AdvanceState(
	newStateRoot runar.ByteString,
	newBlockNumber runar.Bigint,
	batchDataHash runar.ByteString,
	preStateRoot runar.ByteString,
	proofFieldA runar.Bigint,
	proofFieldB runar.Bigint,
	proofFieldC runar.Bigint,
	merkleLeaf runar.ByteString,
	merkleProof runar.ByteString,
	merkleIndex runar.Bigint,
) {
	// 1. Block number must strictly increase
	runar.Assert(newBlockNumber > c.BlockNumber)

	// 2. Pre-state root must match current covenant state
	runar.Assert(preStateRoot == c.StateRoot)

	// 3. Verify Baby Bear field multiplication (simplified proof check)
	runar.Assert(runar.BbFieldMul(proofFieldA, proofFieldB) == proofFieldC)

	// 4. Verify Merkle commitment against the verifying key hash
	computedRoot := runar.MerkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 4)
	runar.Assert(computedRoot == c.VerifyingKeyHash)

	// 5. Batch data hash binding
	expectedBatchHash := runar.Hash256(runar.Cat(preStateRoot, newStateRoot))
	runar.Assert(batchDataHash == expectedBatchHash)

	// 6. Update state
	c.StateRoot = newStateRoot
	c.BlockNumber = newBlockNumber
}
