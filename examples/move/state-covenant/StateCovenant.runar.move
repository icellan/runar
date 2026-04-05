// StateCovenant -- A stateful UTXO chain covenant that guards a state root.
//
// Demonstrates the core pattern for a validity-proof-based state covenant:
// each spend advances the state by providing a new state root, a block number,
// and proof data. The covenant verifies the proof and enforces monotonic
// block number progression.
//
// This contract exercises the key primitives needed for STARK/FRI verification
// on BSV: Baby Bear field arithmetic, SHA-256 Merkle proof verification, and
// hash256 batch data binding -- without implementing the full FRI verifier.
//
// State fields (persisted across UTXO spends via OP_PUSH_TX):
//   - state_root: 32-byte hash representing the current state
//   - block_number: monotonically increasing block counter
//
// Readonly property (baked into locking script at compile time):
//   - verifying_key_hash: commitment to the proof system's verifying key;
//     also used as the expected Merkle root for commitment verification
module StateCovenant {
    use runar::types::{ByteString};
    use runar::math::{bbFieldMul};
    use runar::crypto::{merkleRootSha256, hash256, cat};

    resource struct StateCovenant {
        state_root: ByteString,
        block_number: bigint,
        verifying_key_hash: ByteString,  // readonly -- baked into script at deploy time
    }

    // Advance the covenant state. Verifies proof data and updates state root
    // and block number.
    public fun advance_state(
        contract: &mut StateCovenant,
        new_state_root: ByteString,
        new_block_number: bigint,
        batch_data_hash: ByteString,
        pre_state_root: ByteString,
        proof_field_a: bigint,
        proof_field_b: bigint,
        proof_field_c: bigint,
        merkle_leaf: ByteString,
        merkle_proof: ByteString,
        merkle_index: bigint,
    ) {
        // 1. Block number must strictly increase
        assert!(new_block_number > contract.block_number, 0);

        // 2. Pre-state root must match current covenant state
        assert!(pre_state_root == contract.state_root, 0);

        // 3. Verify Baby Bear field multiplication (simplified proof check)
        assert!(bbFieldMul(proof_field_a, proof_field_b) == proof_field_c, 0);

        // 4. Verify Merkle commitment: the leaf must be in a SHA-256 tree
        //    whose root matches the verifying key hash
        let computed_root: ByteString = merkleRootSha256(merkle_leaf, merkle_proof, merkle_index, 4);
        assert!(computed_root == contract.verifying_key_hash, 0);

        // 5. Batch data hash binding: verify the caller provided the correct
        //    hash256 of the state transition
        let expected_batch_hash: ByteString = hash256(cat(pre_state_root, new_state_root));
        assert!(batch_data_hash == expected_batch_hash, 0);

        // 6. Update state -- compiler auto-enforces output carries new state
        contract.state_root = new_state_root;
        contract.block_number = new_block_number;
    }
}
