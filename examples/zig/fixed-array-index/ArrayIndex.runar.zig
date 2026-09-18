const runar = @import("runar");

// ArrayIndex -- Zig port of
// examples/ts/fixed-array-index/ArrayIndex.runar.ts.
//
// Exercises [4]i64 together with a RUNTIME index read self.table[i].
pub const ArrayIndex = struct {
    pub const Contract = runar.SmartContract;

    table: [4]i64 = .{ 10, 20, 30, 40 },

    pub fn init() ArrayIndex {
        return .{};
    }

    pub fn lookup(self: *const ArrayIndex, i: i64, expected: i64) void {
        runar.assert(self.table[i] == expected);
    }
};
