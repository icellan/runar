const runar = @import("runar");

pub const BitwiseOps = struct {
    pub const Contract = runar.SmartContract;

    a: i64,
    b: i64,

    pub fn init(a: i64, b: i64) BitwiseOps {
        return .{ .a = a, .b = b };
    }

    pub fn testShift(self: *const BitwiseOps, expectedLeft: i64, expectedRight: i64) void {
        const left = self.a << 2;
        const right = self.a >> 1;
        runar.assert(left == expectedLeft);
        runar.assert(right == expectedRight);
    }

    pub fn testBitwise(self: *const BitwiseOps, expectedAnd: i64, expectedOr: i64, expectedXor: i64) void {
        const andResult = self.a & self.b;
        const orResult = self.a | self.b;
        const xorResult = self.a ^ self.b;
        const notResult = ~self.a;
        runar.assert(andResult == expectedAnd);
        runar.assert(orResult == expectedOr);
        runar.assert(xorResult == expectedXor);
        runar.assert(~notResult == self.a);
        runar.assert(~(self.a | self.b) == (notResult & ~self.b));
    }
};
