const runar = @import("runar");

pub const ShiftOps = struct {
    pub const Contract = runar.SmartContract;

    a: i64,

    pub fn init(a: i64) ShiftOps {
        return .{ .a = a };
    }

    pub fn testShift(self: *const ShiftOps, expectedLeft: i64, expectedRight: i64) void {
        const left = self.a << 3;
        const right = self.a >> 2;
        runar.assert(left == expectedLeft);
        runar.assert(right == expectedRight);
    }
};
