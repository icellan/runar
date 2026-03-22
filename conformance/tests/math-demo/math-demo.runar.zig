const runar = @import("runar");

pub const MathDemo = struct {
    pub const Contract = runar.StatefulSmartContract;

    value: i64 = 0,

    pub fn init(value: i64) MathDemo {
        return .{ .value = value };
    }

    pub fn divideBy(self: *MathDemo, divisor: i64) void {
        self.value = runar.safediv(self.value, divisor);
    }

    pub fn withdrawWithFee(self: *MathDemo, amount: i64, feeBps: i64) void {
        const fee = runar.percentOf(amount, feeBps);
        const total = amount + fee;
        runar.assert(total <= self.value);
        self.value = self.value - total;
    }

    pub fn clampValue(self: *MathDemo, lo: i64, hi: i64) void {
        self.value = runar.clamp(self.value, lo, hi);
    }

    pub fn normalize(self: *MathDemo) void {
        self.value = runar.sign(self.value);
    }

    pub fn exponentiate(self: *MathDemo, exp: i64) void {
        self.value = runar.pow(self.value, exp);
    }

    pub fn squareRoot(self: *MathDemo) void {
        self.value = runar.sqrt(self.value);
    }

    pub fn reduceGcd(self: *MathDemo, other: i64) void {
        self.value = runar.gcd(self.value, other);
    }

    pub fn scaleByRatio(self: *MathDemo, numerator: i64, denominator: i64) void {
        self.value = runar.mulDiv(self.value, numerator, denominator);
    }

    pub fn computeLog2(self: *MathDemo) void {
        self.value = runar.log2(self.value);
    }
};
