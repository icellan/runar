const runar = @import("runar");

pub const P256Primitives = struct {
    pub const Contract = runar.SmartContract;

    expectedPoint: runar.ByteString,

    pub fn init(expectedPoint: runar.ByteString) P256Primitives {
        return .{ .expectedPoint = expectedPoint };
    }

    pub fn verify(self: *const P256Primitives, k: i64, basePoint: runar.ByteString) void {
        const result = runar.p256Mul(basePoint, k);
        runar.assert(runar.p256OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }

    pub fn verifyAdd(self: *const P256Primitives, a: runar.ByteString, b: runar.ByteString) void {
        const result = runar.p256Add(a, b);
        runar.assert(runar.p256OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }

    pub fn verifyMulGen(self: *const P256Primitives, k: i64) void {
        _ = self;
        const result = runar.p256MulGen(k);
        runar.assert(runar.p256OnCurve(result));
        runar.assert(result == self.expectedPoint);
    }
};
