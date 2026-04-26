const runar = @import("runar");

pub const Blake3Test = struct {
    pub const Contract = runar.SmartContract;

    expected: runar.ByteString,

    pub fn init(expected: runar.ByteString) Blake3Test {
        return .{ .expected = expected };
    }

    pub fn verifyCompress(self: *const Blake3Test, chainingValue: runar.ByteString, block: runar.ByteString) void {
        const result = runar.blake3Compress(chainingValue, block);
        runar.assert(runar.bytesEq(result, self.expected));
    }

    pub fn verifyHash(self: *const Blake3Test, message: runar.ByteString) void {
        const result = runar.blake3Hash(message);
        runar.assert(runar.bytesEq(result, self.expected));
    }
};
