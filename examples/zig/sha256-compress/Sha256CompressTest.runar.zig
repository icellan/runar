const runar = @import("runar");

pub const Sha256CompressTest = struct {
    pub const Contract = runar.SmartContract;

    expected: runar.ByteString,

    pub fn init(expected: runar.ByteString) Sha256CompressTest {
        return .{ .expected = expected };
    }

    pub fn verify(self: *const Sha256CompressTest, state: runar.ByteString, block: runar.ByteString) void {
        runar.assert(runar.bytesEq(runar.sha256Compress(state, block), self.expected));
    }
};
