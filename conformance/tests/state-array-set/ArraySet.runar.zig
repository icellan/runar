const runar = @import("runar");

// ArraySet -- Zig port of ArraySet.runar.ts.
pub const ArraySet = struct {
    pub const Contract = runar.StatefulSmartContract;

    slots: [4]i64 = .{ 0, 0, 0, 0 },

    pub fn init() ArraySet {
        return .{};
    }

    pub fn put(self: *ArraySet, i: i64, v: i64) void {
        self.slots[i] = v;
        runar.assert(true);
    }
};
