const runar = @import("runar");

pub const PropertyInitializers = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    maxCount: i64,
    active: runar.Readonly(bool) = true,

    pub fn init(maxCount: i64) PropertyInitializers {
        return .{ .maxCount = maxCount };
    }

    pub fn increment(self: *PropertyInitializers, amount: i64) void {
        runar.assert(self.active);
        self.count = self.count + amount;
        runar.assert(self.count <= self.maxCount);
    }

    pub fn reset(self: *PropertyInitializers) void {
        self.count = 0;
    }
};
