const runar = @import("runar");

pub const DataOutputTest = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) DataOutputTest {
        return .{ .count = count };
    }

    pub fn publish(self: *DataOutputTest, ctx: runar.StatefulContext, payload: runar.ByteString) void {
        self.count = self.count + 1;
        ctx.addDataOutput(0, payload);
    }
};
