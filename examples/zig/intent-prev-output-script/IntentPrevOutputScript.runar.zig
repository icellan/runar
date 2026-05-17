const runar = @import("runar");

pub const IntentPrevOutputScript = struct {
    pub const Contract = runar.StatefulSmartContract;

    expectedHash: runar.ByteString,
    count: i64 = 0,

    pub fn init(expectedHash: runar.ByteString, count: i64) IntentPrevOutputScript {
        return .{ .expectedHash = expectedHash, .count = count };
    }

    pub fn bind(self: *IntentPrevOutputScript) void {
        const s = runar.extractPrevOutputScript(0, self.expectedHash);
        runar.assert(runar.len(s) > 0);
        self.count = self.count + 1;
    }
};
