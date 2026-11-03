// N-491: TS surface-parser operand anchor parity. A boolean identifier as the right operand of `<`.
// TS must anchor the refusal on this surface exactly where it does on .runar.ts
// (see n491-operand-anchor-surface-matrix.test.ts).
const runar = @import("runar");

pub const Anchor = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) Anchor {
        return .{ .t = t };
    }

    pub fn go(self: *const Anchor, x: i64, flag: bool) void {
        runar.assert(x < flag);
    }
};
