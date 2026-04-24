const runar = @import("runar");

pub const ShiftOps = struct {
    pub const Contract = runar.SmartContract;

    a: i64,

    pub fn init(a: i64) ShiftOps {
        return .{ .a = a };
    }

    pub fn testShift(self: *const ShiftOps) void {
        const left = self.a << 3;
        const right = self.a >> 2;
        runar.assert(left >= 0 or left < 0);
        runar.assert(right >= 0 or right < 0);
    }
};
