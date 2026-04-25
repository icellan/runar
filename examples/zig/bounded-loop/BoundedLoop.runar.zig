const runar = @import("runar");

pub const BoundedLoop = struct {
    pub const Contract = runar.SmartContract;

    expectedSum: i64,

    pub fn init(expectedSum: i64) BoundedLoop {
        return .{ .expectedSum = expectedSum };
    }

    pub fn verify(self: *const BoundedLoop, start: i64) void {
        var sum: i64 = 0;
        var i: i64 = 0;
        while (i < 5) : (i += 1) {
            sum = sum + start + i;
        }
        runar.assert(sum == self.expectedSum);
    }
};
