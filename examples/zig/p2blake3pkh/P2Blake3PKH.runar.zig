const runar = @import("runar");

pub const P2Blake3PKH = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.ByteString,

    pub fn init(pubKeyHash: runar.ByteString) P2Blake3PKH {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const P2Blake3PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.blake3Hash(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
