const runar = @import("runar");

// LoopShapes -- Zig port. A NON-ZERO loop start (R-102).
pub const LoopShapes = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) LoopShapes {
        return .{ .target = target };
    }

    pub fn verify(self: *const LoopShapes, seed: i64) void {
        var acc: i64 = seed;
        var i: i64 = 3;
        while (i < 7) : (i += 1) {
            acc = acc + i;
        }
        runar.assert(acc == self.target);
    }
};
