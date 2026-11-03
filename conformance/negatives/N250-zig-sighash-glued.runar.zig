// N-244: the sighash marker glued to its flag list on the Zig surface.
// Only .runar.ts honours the directive; every other surface must refuse ANY
// occurrence of the marker (N-039's rule), not just a word-bounded one, with
// the one shared "not supported by the Zig surface parser" message.
// Before N-244 every tier read the glued form as prose and compiled ALL|FORKID.
const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Counter {
        return .{ .count = count };
    }

    // @sighashSINGLE|FORKID
    pub fn increment(self: *Counter) void {
        self.count += 1;
    }
};
