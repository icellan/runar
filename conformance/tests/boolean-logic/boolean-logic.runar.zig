const runar = @import("runar");

pub const BooleanLogic = struct {
    pub const Contract = runar.SmartContract;

    threshold: i64,

    pub fn init(threshold: i64) BooleanLogic {
        return .{ .threshold = threshold };
    }

    pub fn verify(self: *const BooleanLogic, a: i64, b: i64, flag: bool) void {
        const aAboveThreshold = a > self.threshold;
        const bAboveThreshold = b > self.threshold;
        const bothAbove = aAboveThreshold and bAboveThreshold;
        const eitherAbove = aAboveThreshold or bAboveThreshold;
        const notFlag = !flag;
        runar.assert(bothAbove or (eitherAbove and notFlag));
    }
};
