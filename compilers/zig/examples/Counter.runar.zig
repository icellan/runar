const runar = @import("runar");

pub const Counter = struct {
    pub const Contract = runar.StatefulSmartContract;

    owner: runar.PubKey,
    count: i64 = 0,

    pub fn init(owner: runar.PubKey, count: i64) Counter {
        return .{ .owner = owner, .count = count };
    }

    pub fn increment(self: *Counter, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
        self.count += 1;
        self.addOutput(1, self.count);
    }

    pub fn decrement(self: *Counter, sig: runar.Sig) void {
        runar.assert(runar.checkSig(sig, self.owner));
        runar.assert(self.count > 0);
        self.count -= 1;
        self.addOutput(1, self.count);
    }
};
