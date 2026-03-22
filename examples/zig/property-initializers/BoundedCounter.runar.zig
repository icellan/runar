const runar = @import("runar");

pub const BoundedCounter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    maxCount: i64,
    active: runar.Readonly(bool) = true,

    pub fn init(maxCount: i64) BoundedCounter {
        return .{
            .maxCount = maxCount,
        };
    }

    pub fn increment(self: *BoundedCounter, amount: i64) void {
        runar.assert(self.active);
        self.count = self.count + amount;
        runar.assert(self.count <= self.maxCount);
    }

    pub fn reset(self: *BoundedCounter) void {
        self.count = 0;
    }
};
