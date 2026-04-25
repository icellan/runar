const runar = @import("runar");

pub const DataOutputTest = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) DataOutputTest {
        return .{ .count = count };
    }

    pub fn publish(self: *DataOutputTest, payload: runar.ByteString) void {
        self.count = self.count + 1;
        self.addDataOutput(0, payload);
    }
};
