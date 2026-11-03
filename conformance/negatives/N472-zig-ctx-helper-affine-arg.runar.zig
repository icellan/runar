// N-472: typecheck diagnostic anchor parity. `self.check(ctx, sig)` passes a
// StatefulContext handle that every tier drops from the argument list; the
// location of the arguments that remain must keep its index, so the second
// consumption of `sig` is anchored at that argument.
// Every tier must anchor the refusal where the TypeScript reference does
// (see n233-diagnostic-anchor-parity.test.ts).
const runar = @import("runar");

pub const Anchor = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64 = 0,
    owner: runar.PubKey = runar.hexToBytes("000000000000000000000000000000000000000000000000000000000000000000"),

    pub fn init(count: i64, owner: runar.PubKey) Anchor {
        return .{ .count = count, .owner = owner };
    }

    fn check(self: *const Anchor, ctx: runar.StatefulContext, s: runar.Sig) void {
        _ = ctx;
        runar.assert(runar.checkSig(s, self.owner));
    }

    pub fn spend(self: *Anchor, ctx: runar.StatefulContext, sig: runar.Sig) void {
        self.check(ctx, sig);
        self.check(ctx, sig);
        runar.assert(true);
    }
};
