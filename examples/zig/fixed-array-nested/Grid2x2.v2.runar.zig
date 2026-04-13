const runar = @import("runar");

// Grid2x2 -- minimal nested FixedArray acceptance contract for the Zig
// port of the FixedArray feature. Mirrors the TypeScript spike in
// examples/ts/fixed-array-nested/Grid2x2.v2.runar.ts.
//
// The expand-fixed-arrays pass desugars `grid` into four scalar siblings
// `grid__0__0`, `grid__0__1`, `grid__1__0`, `grid__1__1`. The iterative
// regrouper in the artifact assembler rebuilds a single nested FixedArray
// state field so the SDK exposes `state.grid` as a real nested array.
pub const Grid2x2 = struct {
    pub const Contract = runar.StatefulSmartContract;

    grid: [2][2]i64 = .{ .{ 0, 0 }, .{ 0, 0 } },

    pub fn init() Grid2x2 {
        return .{};
    }

    pub fn set00(self: *Grid2x2, v: i64) void {
        self.grid[0][0] = v;
        runar.assert(true);
    }

    pub fn set01(self: *Grid2x2, v: i64) void {
        self.grid[0][1] = v;
        runar.assert(true);
    }

    pub fn set10(self: *Grid2x2, v: i64) void {
        self.grid[1][0] = v;
        runar.assert(true);
    }

    pub fn set11(self: *Grid2x2, v: i64) void {
        self.grid[1][1] = v;
        runar.assert(true);
    }

    pub fn read00(self: *const Grid2x2) void {
        runar.assert(self.grid[0][0] == self.grid[0][0]);
    }
};
