const runar = @import("runar");

pub const Sha256FinalizeTest = struct {
    pub const Contract = runar.SmartContract;

    expected: runar.ByteString,

    pub fn init(expected: runar.ByteString) Sha256FinalizeTest {
        return .{ .expected = expected };
    }

    pub fn verify(
        self: *const Sha256FinalizeTest,
        state: runar.ByteString,
        remaining: runar.ByteString,
        msgBitLen: i64,
    ) void {
        runar.assert(runar.bytesEq(runar.sha256Finalize(state, remaining, msgBitLen), self.expected));
    }
};
