const runar = @import("runar");

// EmbedTags -- Zig port of
// examples/ts/compiler-directives/EmbedTags.runar.ts.
//
// EmbedAlways(T) on a fixed-array field applies to every expanded slot:
// all three are kept although unlock reads only tags[1].
pub const EmbedTags = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,
    tags: runar.EmbedAlways([3]i64) = .{ 7, 9, 11 },

    pub fn init(pubKeyHash: runar.Addr) EmbedTags {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const EmbedTags, sig: runar.Sig, pubKey: runar.PubKey, amount: i64) void {
        runar.assert(amount >= self.tags[1]);
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
