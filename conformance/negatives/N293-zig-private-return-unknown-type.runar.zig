// N-331: a Zig-surface private function whose return type names a type that
// does not exist. On this surface the return slot also carries the
// runar.Sighash(...) directive, so the check must not mistake that for a type.
const runar = @import("runar");

pub const PrivateReturnUnknownType = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) PrivateReturnUnknownType {
        return .{ .t = t };
    }

    fn helper(x: i64) TTT {
        return 1;
    }

    pub fn verify(self: *const PrivateReturnUnknownType, a: i64) void {
        runar.assert(a == self.t);
    }
};
