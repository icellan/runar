const runar = @import("runar");

// SingleCounter -- Zig port of
// examples/ts/sighash-single-stateful/SingleCounter.runar.ts.
//
// bump's return type runar.Sighash("SINGLE|FORKID") (N-093) declares that its
// auto-injected continuation commits only the output at its own index: no
// change segment and no _changePKH / _changeAmount parameter (N-038). SINGLE
// does not pin the continuation's value, so bump re-creates it at the full
// input amount read from the preimage. reset keeps ALL|FORKID.
pub const SingleCounter = struct {
    pub const Contract = runar.StatefulSmartContract;

    count: i64,

    pub fn init(count: i64) SingleCounter {
        return .{ .count = count };
    }

    pub fn bump(self: *SingleCounter, ctx: runar.StatefulContext) runar.Sighash("SINGLE|FORKID") {
        self.addOutput(runar.extractAmount(ctx.txPreimage), self.count + 1);
    }

    pub fn reset(self: *SingleCounter) void {
        runar.assert(self.count > 0);
        self.count = 0;
    }
};
