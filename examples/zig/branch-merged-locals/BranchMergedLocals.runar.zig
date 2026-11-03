const runar = @import("runar");

// BranchMergedLocals -- regression fixture for the branch-merged-local
// miscompilation reported privately on 2026-08-03: two locals initialised from
// state, the arms of an `if` reassigning DIFFERENT ones, both feeding the
// continuation. Post-branch references used to resolve to the dead pre-branch
// binding.
pub const BranchMergedLocals = struct {
    pub const Contract = runar.StatefulSmartContract;

    a: i64 = 0,
    b: i64 = 0,

    pub fn init(a: i64, b: i64) BranchMergedLocals {
        return .{ .a = a, .b = b };
    }

    pub fn bid(self: *BranchMergedLocals, ctx: runar.StatefulContext, amount: i64, toFirst: i64) void {
        var na = self.a;
        var nb = self.b;
        if (toFirst > 0) {
            na = amount;
        } else {
            nb = amount;
        }
        ctx.addOutput(1000, .{ na, nb });
    }
};
