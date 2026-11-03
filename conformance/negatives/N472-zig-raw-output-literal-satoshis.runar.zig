// N-472: typecheck diagnostic anchor parity. A boolean literal as the
// addRawOutput satoshis argument, Zig surface.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
const runar = @import("runar");

pub const Anchor = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,

    pub fn init(count: i64) Anchor {
        return .{ .count = count };
    }

    pub fn go(self: *Anchor, ctx: runar.StatefulContext, payload: runar.ByteString) void {
        ctx.addRawOutput(true, payload);
        self.count = self.count + 1;
        ctx.addOutput(0, .{self.count});
    }
};
