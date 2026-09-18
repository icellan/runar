const runar = @import("runar");

// R-102 — `while (i != N)` is not a loop bound, and six tiers always said so.
//
// `spec/grammar.md`'s RelOp production is `< | <= | > | >=`. The ANF loop node
// carries `{count, iterVar, start, step}` and synthesizes iteration k as
// `start + k*step`, so the trip count has to come out of the comparison — and
// `!=` carries no direction at all. TypeScript, Go, Rust, Python, Ruby and Java
// all refuse the program below from ANF lowering ("For loop counting up (i++)
// must use '<' or '<='").
//
// The Zig tier accepted it, alone, on its own surface. That is a frontend
// parity break the corpus never covered: no fixture spells a `!=` loop, so
// --parser-only, --multi-format and --ir-parity were all green with one tier
// compiling a program the other six rejected.
//
// And it accepted it WRONGLY. With no direction available it defaulted to
// ascending, so the loop below unrolled `bound - start` = 0 - 4 times, i.e.
// ZERO — the same dropped body as the Move `while`-fold defect, reached from a
// different surface. Making it merely CORRECT would have left one tier
// accepting what six refuse, so this converges onto the spec instead.
pub const ZigLoopNeqCondition = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) ZigLoopNeqCondition {
        return .{ .target = target };
    }

    pub fn verify(self: *const ZigLoopNeqCondition, seed: i64) void {
        var acc: i64 = seed;
        var i: i64 = 4;
        while (i != 0) : (i -= 1) {
            acc = acc + i;
        }
        runar.assert(acc == self.target);
    }
};
