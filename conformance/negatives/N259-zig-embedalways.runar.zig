// N-268: an `embedAlways` marker on a readonly field on the Zig surface.
// Only .runar.ts honours the directive; every other surface must refuse it
// with the one shared "not supported by the Zig surface parser" message
// (mirrors N-244's sighash fix — before N-268 the Zig, Ruby and Java tiers
// each used their own, differently worded text here).
// With the marker replaced by prose, metadataId is an ordinary unreferenced
// readonly field: every tier eliminates it by DCE, so this compiles to the
// same P2PKH-shaped script everywhere.
const runar = @import("runar");

pub const Meta = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,
    // @embedAlways
    metadataId: runar.ByteString,

    pub fn init(pubKeyHash: runar.Addr, metadataId: runar.ByteString) Meta {
        return .{ .pubKeyHash = pubKeyHash, .metadataId = metadataId };
    }

    pub fn unlock(self: *const Meta, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
