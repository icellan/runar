// F-026: a .runar.zig argument list without the comma Zig requires. The
// tokenizer used to split `0b1010` into `0` and `b1010`, and this loop then
// took `b1010` as a second argument to runar.assert: `amount > 0` plus an
// ignored message. The same shape is written out here with a space, so the
// refusal rests on the comma rule alone. Every tier must refuse with:
//   expected ',' between list elements
const runar = @import("runar");

pub const T = struct {
    pub const Contract = runar.SmartContract;

    target: i64,

    pub fn init(target: i64) T {
        return .{ .target = target };
    }

    pub fn verify(self: *const T, amount: i64, b1010: runar.ByteString) void {
        _ = self;
        runar.assert(amount > 0 b1010);
    }
};
