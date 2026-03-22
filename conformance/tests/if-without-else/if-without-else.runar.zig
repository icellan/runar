const runar = @import("runar");

pub const IfWithoutElse = struct {
    pub const Contract = runar.SmartContract;

    threshold: i64,

    pub fn init(threshold: i64) IfWithoutElse {
        return .{ .threshold = threshold };
    }

    pub fn check(self: *const IfWithoutElse, a: i64, b: i64) void {
        var count: i64 = 0;
        if (a > self.threshold) {
            count = count + 1;
        }
        if (b > self.threshold) {
            count = count + 1;
        }
        runar.assert(count > 0);
    }
};
