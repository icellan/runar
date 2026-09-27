// PropertyShadow — N-016 conformance fixture. A local that shares a field's
// name never captures `self.<field>`.
const runar = @import("runar");

pub const PropertyShadow = struct {
    pub const Contract = runar.StatefulSmartContract;

    target: i64,
    count: i64 = 0,

    pub fn init(target: i64, count: i64) PropertyShadow {
        return .{ .target = target, .count = count };
    }

    pub fn bump(self: *PropertyShadow, n: i64) void {
        const target = n + 1;
        runar.assert(target == self.target);
        const count = n;
        self.count = self.count + count;
        runar.assert(self.count > count);
    }
};
