const runar = @import("runar");

pub const CrossCovenantRef = struct {
    pub const Contract = runar.SmartContract;

    sourceScriptHash: runar.ByteString,

    pub fn init(sourceScriptHash: runar.ByteString) CrossCovenantRef {
        return .{ .sourceScriptHash = sourceScriptHash };
    }

    /// Verify a referenced output and extract a 32-byte state root from it.
    pub fn verifyAndExtract(
        self: *const CrossCovenantRef,
        referencedOutput: runar.ByteString,
        expectedStateRoot: runar.ByteString,
        stateRootOffset: i64,
    ) void {
        // Step 1: Hash the referenced output and verify it matches the known script hash.
        const outputHash = runar.hash256(referencedOutput);
        runar.assert(runar.bytesEq(outputHash, self.sourceScriptHash));

        // Step 2: Extract the state root from the referenced output.
        const stateRoot = runar.substr(referencedOutput, stateRootOffset, 32);

        // Step 3: Verify the extracted state root matches the expected value.
        runar.assert(runar.bytesEq(stateRoot, expectedStateRoot));
    }

    /// Verify a referenced output and extract a numeric value from it.
    pub fn verifyAndExtractNumeric(
        self: *const CrossCovenantRef,
        referencedOutput: runar.ByteString,
        expectedValue: i64,
        valueOffset: i64,
        valueLen: i64,
    ) void {
        const outputHash = runar.hash256(referencedOutput);
        runar.assert(runar.bytesEq(outputHash, self.sourceScriptHash));

        const valueBytes = runar.substr(referencedOutput, valueOffset, valueLen);
        const value = runar.bin2num(valueBytes);
        runar.assert(value == expectedValue);
    }
};
