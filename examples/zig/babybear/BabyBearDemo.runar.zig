const runar = @import("runar");

pub const BabyBearDemo = struct {
    pub const Contract = runar.SmartContract;

    pub fn init() BabyBearDemo {
        return .{};
    }

    pub fn checkAdd(self: *const BabyBearDemo, a: i64, b: i64, expected: i64) void {
        _ = self;
        runar.assert(runar.bbFieldAdd(a, b) == expected);
    }

    pub fn checkSub(self: *const BabyBearDemo, a: i64, b: i64, expected: i64) void {
        _ = self;
        runar.assert(runar.bbFieldSub(a, b) == expected);
    }

    pub fn checkMul(self: *const BabyBearDemo, a: i64, b: i64, expected: i64) void {
        _ = self;
        runar.assert(runar.bbFieldMul(a, b) == expected);
    }

    pub fn checkInv(self: *const BabyBearDemo, a: i64) void {
        _ = self;
        const inv = runar.bbFieldInv(a);
        runar.assert(runar.bbFieldMul(a, inv) == 1);
    }

    pub fn checkAddSubRoundtrip(self: *const BabyBearDemo, a: i64, b: i64) void {
        _ = self;
        const sum = runar.bbFieldAdd(a, b);
        const result = runar.bbFieldSub(sum, b);
        runar.assert(result == a);
    }

    pub fn checkDistributive(self: *const BabyBearDemo, a: i64, b: i64, c: i64) void {
        _ = self;
        const lhs = runar.bbFieldMul(a, runar.bbFieldAdd(b, c));
        const rhs = runar.bbFieldAdd(runar.bbFieldMul(a, b), runar.bbFieldMul(a, c));
        runar.assert(lhs == rhs);
    }
};
