const runar = @import("runar");

// StatefulTerminalLoop -- a TERMINAL stateful method (no state write, so no
// injected continuation assert) whose bounded loop of asserts is followed by a
// final assert, which is the script result. Without it the method is refused
// in every tier (conformance/negatives N547).
pub const StatefulTerminalLoop = struct {
    pub const Contract = runar.StatefulSmartContract;

    floor: i64 = 0,
    count: i64 = 0,

    pub fn init(floor: i64, count: i64) StatefulTerminalLoop {
        return .{ .floor = floor, .count = count };
    }

    pub fn close(self: *StatefulTerminalLoop, x: i64) void {
        var i: i64 = 0;
        while (i < 2) : (i += 1) {
            runar.assert(x >= self.floor + i);
        }
        runar.assert(x > self.count);
    }
};
