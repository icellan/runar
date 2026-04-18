const runar = @import("runar");

pub const BitwiseOps = struct {
    pub const Contract = runar.SmartContract;

    a: i64,
    b: i64,

    pub fn init(a: i64, b: i64) BitwiseOps {
        return .{ .a = a, .b = b };
    }

    pub fn testShift(self: *const BitwiseOps) void {
        const left = self.a << 2;
        const right = self.a >> 1;
        runar.assert(left >= 0 or left < 0);
        runar.assert(right >= 0 or right < 0);
        runar.assert(true);
    }

    pub fn testBitwise(self: *const BitwiseOps) void {
        const andResult = self.a & self.b;
        const orResult = self.a | self.b;
        const xorResult = self.a ^ self.b;
        const notResult = ~self.a;
        runar.assert(andResult >= 0 or andResult < 0);
        runar.assert(orResult >= 0 or orResult < 0);
        runar.assert(xorResult >= 0 or xorResult < 0);
        runar.assert(notResult >= 0 or notResult < 0);
        runar.assert(true);
    }
};
