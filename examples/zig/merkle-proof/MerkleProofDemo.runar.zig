const runar = @import("runar");

pub const MerkleProofDemo = struct {
    pub const Contract = runar.SmartContract;

    expectedRoot: runar.ByteString,

    pub fn init(expectedRoot: runar.ByteString) MerkleProofDemo {
        return .{ .expectedRoot = expectedRoot };
    }

    pub fn verifySha256(self: *const MerkleProofDemo, leaf: runar.ByteString, proof: runar.ByteString, index: i64) void {
        runar.assert(runar.bytesEq(runar.merkleRootSha256(leaf, proof, index, 4), self.expectedRoot));
    }

    pub fn verifyHash256(self: *const MerkleProofDemo, leaf: runar.ByteString, proof: runar.ByteString, index: i64) void {
        runar.assert(runar.bytesEq(runar.merkleRootHash256(leaf, proof, index, 4), self.expectedRoot));
    }
};
