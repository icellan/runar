const runar = @import("runar");

pub const IntentCurrentBlockHeight = struct {
    pub const Contract = runar.StatefulSmartContract;

    deadline: i64,
    count: i64 = 0,

    pub fn init(deadline: i64, count: i64) IntentCurrentBlockHeight {
        return .{ .deadline = deadline, .count = count };
    }

    pub fn spend(self: *IntentCurrentBlockHeight) void {
        const h = runar.currentBlockHeight();
        runar.assert(h <= self.deadline);
        self.count = self.count + 1;
    }
};
