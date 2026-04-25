const runar = @import("runar");

pub const IfElse = struct {
    pub const Contract = runar.SmartContract;

    limit: i64,

    pub fn init(limit: i64) IfElse {
        return .{ .limit = limit };
    }

    pub fn check(self: *const IfElse, value: i64, mode: bool) void {
        var result: i64 = 0;
        if (mode) {
            result = value + self.limit;
        } else {
            result = value - self.limit;
        }
        runar.assert(result > 0);
    }
};
