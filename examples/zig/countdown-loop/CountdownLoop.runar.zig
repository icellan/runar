const runar = @import("runar");

// CountdownLoop -- Zig port. `step = -1` (R-102).
//
// This surface could always SPELL the countdown; the Zig tier just never read
// the direction off the comparison, so `while (i > 1) : (i -= 1)` unrolled
// zero times there while the other six tiers lowered a real countdown from the
// same bytes. See CountdownLoop.runar.ts.
pub const CountdownLoop = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) CountdownLoop {
        return .{ .target = target };
    }

    pub fn verify(self: *const CountdownLoop, seed: i64) void {
        var acc: i64 = seed;
        var i: i64 = 5;
        while (i > 1) : (i -= 1) {
            acc = acc + i;
        }
        runar.assert(acc == self.target);
    }
};
