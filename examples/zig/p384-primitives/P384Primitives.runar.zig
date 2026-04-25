const runar = @import("runar");

pub const P384Primitives = struct {
    pub const Contract = runar.SmartContract;

    expectedPoint: runar.P384Point,

    pub fn init(expectedPoint: runar.P384Point) P384Primitives {
        return .{ .expectedPoint = expectedPoint };
    }

    pub fn verify(self: *const P384Primitives, k: i64, basePoint: runar.P384Point) void {
        const result = runar.p384Mul(basePoint, k);
        runar.assert(runar.p384OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }

    pub fn verifyAdd(self: *const P384Primitives, a: runar.P384Point, b: runar.P384Point) void {
        const result = runar.p384Add(a, b);
        runar.assert(runar.p384OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }

    pub fn verifyMulGen(self: *const P384Primitives, k: i64) void {
        _ = self;
        const result = runar.p384MulGen(k);
        runar.assert(runar.p384OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }
};
