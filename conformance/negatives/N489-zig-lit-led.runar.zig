// N-489: typecheck diagnostic anchor parity. A bigint composite whose first token is a literal, as the left operand of `&&`.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
const runar = @import("runar");

pub const Anchor = struct {
    pub const Contract = runar.SmartContract;

    t: i64,

    pub fn init(t: i64) Anchor {
        return .{ .t = t };
    }

    pub fn go(self: *const Anchor, x: i64, flag: bool) void {
        runar.assert(5 + 1 and flag);
    }
};
