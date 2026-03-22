const runar = @import("runar");

pub const Arithmetic = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) Arithmetic {
        return .{ .target = target };
    }

    pub fn verify(self: *const Arithmetic, a: i64, b: i64) void {
        const sum = a + b;
        const diff = a - b;
        const prod = a * b;
        const quot = @divTrunc(a, b);
        const result = sum + diff + prod + quot;
        runar.assert(result == self.target);
    }
};
