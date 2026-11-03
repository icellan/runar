// N-472: typecheck diagnostic anchor parity. A bigint composite as the
// addRawOutput scriptBytes argument, Zig surface.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
const runar = @import("runar");

pub const Anchor = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Anchor {
        return .{ .count = count };
    }

    pub fn go(self: *Anchor, ctx: runar.StatefulContext, n: i64) void {
        ctx.addRawOutput(1000, n + 1);
        self.count = self.count + 1;
        ctx.addOutput(0, .{self.count});
    }
};
