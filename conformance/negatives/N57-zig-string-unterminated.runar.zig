// F-011: an unterminated .runar.zig string literal that swallowed the
// runar.assert on the next line in run-to-next-quote tokenizers.
// Every tier must refuse with:
//   unterminated string literal
const runar = @import("runar");

pub const Guarded = struct {
    pub const Contract = runar.SmartContract;

    pub fn unlock(self: *const Guarded, y: runar.Bigint) void {
        _ = self;
        const tag: runar.ByteString = "cafe
        runar.assert(y < 5);
        // ";
        runar.assert(y >= 0);
        _ = tag;
    }
};
