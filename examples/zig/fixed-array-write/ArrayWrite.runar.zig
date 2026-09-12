const runar = @import("runar");

// ArrayWrite -- Zig port of
// examples/ts/fixed-array-write/ArrayWrite.runar.ts.
pub const ArrayWrite = struct {
    pub const Contract = runar.StatefulSmartContract;

    table: [4]i64 = .{ 0, 0, 0, 0 },

    pub fn init() ArrayWrite {
        return .{};
    }

    pub fn bump(self: *ArrayWrite, i: i64) void {
        self.table[i] += 1;
        runar.assert(true);
    }
};
