const runar = @import("runar");

pub const RawOutputTest = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) RawOutputTest {
        return .{ .count = count };
    }

    pub fn sendToScript(self: *RawOutputTest, scriptBytes: runar.ByteString) void {
        self.addRawOutput(1000, scriptBytes);
        self.count = self.count + 1;
        self.addOutput(0, self.count);
    }
};
