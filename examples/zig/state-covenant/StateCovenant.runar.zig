const runar = @import("runar");

pub const StateCovenant = struct {
    pub const Contract = runar.StatefulSmartContract;

    stateRoot: runar.ByteString = "",
    blockNumber: i64 = 0,
    verifyingKeyHash: runar.Readonly(runar.ByteString),

    pub fn init(stateRoot: runar.ByteString, blockNumber: i64, verifyingKeyHash: runar.ByteString) StateCovenant {
        return .{ .stateRoot = stateRoot, .blockNumber = blockNumber, .verifyingKeyHash = verifyingKeyHash };
    }

    pub fn advanceState(
        self: *StateCovenant,
        newStateRoot: runar.ByteString,
        newBlockNumber: i64,
        batchDataHash: runar.ByteString,
        preStateRoot: runar.ByteString,
        proofFieldA: i64,
        proofFieldB: i64,
        proofFieldC: i64,
        merkleLeaf: runar.ByteString,
        merkleProof: runar.ByteString,
        merkleIndex: i64,
    ) void {
        // Block number must strictly increase
        runar.assert(newBlockNumber > self.blockNumber);

        // Pre-state root must match current covenant state
        runar.assert(preStateRoot == self.stateRoot);

        // Verify Baby Bear field multiplication (simplified proof check)
        runar.assert(runar.bbFieldMul(proofFieldA, proofFieldB) == proofFieldC);

        // Verify Merkle commitment
        const computedRoot = runar.merkleRootSha256(merkleLeaf, merkleProof, merkleIndex, 4);
        runar.assert(computedRoot == self.verifyingKeyHash);

        // Batch data hash binding
        const expectedBatchHash = runar.hash256(runar.cat(preStateRoot, newStateRoot));
        runar.assert(batchDataHash == expectedBatchHash);

        // Update state
        self.stateRoot = newStateRoot;
        self.blockNumber = newBlockNumber;
    }
};
