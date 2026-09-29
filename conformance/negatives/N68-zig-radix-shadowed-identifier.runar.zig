// F-026: an upper-case radix prefix next to a parameter spelled like its tail.
// Zig spells the binary prefix `0b` only, so `0B1010` is not a Zig integer
// literal. Pre-fix, the reference tokenizer read it as `0` followed by the
// identifier `B1010` and, because .runar.zig call arguments needed no commas,
// absorbed the identifier as a second argument: the guard compiled to
// `amount > 0` (7c00a069767c87). The lower-case form of this shape passed
// @bsv/sdk Spend.validate with amount = 5 in attempt 1. Every tier must
// refuse with:
//   invalid Zig integer literal '0B1010'
const runar = @import("runar");

pub const T = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) T {
        return .{ .target = target };
    }

    pub fn verify(self: *const T, amount: i64, B1010: runar.ByteString) void {
        _ = self;
        runar.assert(amount > 0B1010);
        runar.assert(B1010 == B1010);
    }
};
