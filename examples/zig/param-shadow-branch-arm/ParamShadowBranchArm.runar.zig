// ParamShadowBranchArm — N-007 conformance fixture. The parameter `count`
// shares the field's name; inside the `if` arm it is still the parameter.
const runar = @import("runar");

pub const ParamShadowBranchArm = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) ParamShadowBranchArm {
        return .{ .count = count };
    }

    pub fn set(self: *ParamShadowBranchArm, count: i64, flag: bool) void {
        if (flag) {
            runar.assert(count == 5);
        }
        self.count = count;
    }
};
