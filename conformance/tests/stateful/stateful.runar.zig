const runar = @import("runar");

pub const Stateful = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    maxCount: i64,

    pub fn init(count: i64, maxCount: i64) Stateful {
        return .{ .count = count, .maxCount = maxCount };
    }

    pub fn increment(self: *Stateful, amount: i64) void {
        self.count = self.count + amount;
        runar.assert(self.count <= self.maxCount);
    }

    pub fn reset(self: *Stateful) void {
        self.count = 0;
    }
};
