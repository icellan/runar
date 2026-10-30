const runar = @import("runar");

pub const CondWriteMultiField = struct {
    pub const Contract = runar.StatefulSmartContract;

    a: i64 = 0,
    b: i64 = 0,

    pub fn init(a: i64, b: i64) CondWriteMultiField {
        return .{ .a = a, .b = b };
    }

    pub fn bump(self: *CondWriteMultiField, ctx: runar.StatefulContext, flag: i64) void {
        if (flag > 0) {
            self.a = self.a + 1;
            self.b = self.b + 2;
        }
        ctx.addOutput(1000, .{ self.a, self.b });
    }
};
