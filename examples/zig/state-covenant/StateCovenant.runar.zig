const runar = @import("runar");

pub const StateCovenant = struct {
    pub const Contract = runar.StatefulSmartContract;

    state_root: runar.ByteString,
    block_number: i64,
    verifying_key_hash: runar.Readonly(runar.ByteString),

    pub fn init(state_root: runar.ByteString, block_number: i64, verifying_key_hash: runar.ByteString) StateCovenant {
        return .{ .state_root = state_root, .block_number = block_number, .verifying_key_hash = verifying_key_hash };
    }

    pub fn advanceState(
        self: *StateCovenant,
        new_state_root: runar.ByteString,
        new_block_number: i64,
        batch_data_hash: runar.ByteString,
        pre_state_root: runar.ByteString,
        proof_field_a: i64,
        proof_field_b: i64,
        proof_field_c: i64,
        merkle_leaf: runar.ByteString,
        merkle_proof: runar.ByteString,
        merkle_index: i64,
    ) void {
        // Block number must strictly increase
        runar.assert(new_block_number > self.block_number);

        // Pre-state root must match current covenant state
        runar.assert(pre_state_root == self.state_root);

        // Verify Baby Bear field multiplication (simplified proof check)
        runar.assert(runar.bbFieldMul(proof_field_a, proof_field_b) == proof_field_c);

        // Verify Merkle commitment
        const computed_root = runar.merkleRootSha256(merkle_leaf, merkle_proof, merkle_index, 4);
        runar.assert(computed_root == self.verifying_key_hash);

        // Batch data hash binding
        const expected_batch_hash = runar.hash256(runar.cat(pre_state_root, new_state_root));
        runar.assert(batch_data_hash == expected_batch_hash);

        // Update state
        self.state_root = new_state_root;
        self.block_number = new_block_number;
    }
};
