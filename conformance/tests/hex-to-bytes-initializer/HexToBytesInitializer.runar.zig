const runar = @import("runar");

pub const HexToBytesInitializer = struct {
    pub const Contract = runar.SmartContract;

    p2pkhPrefix: runar.Readonly(runar.ByteString) = runar.hexToBytes("1976a914"),
    p2pkhSuffix: runar.Readonly(runar.ByteString) = runar.hexToBytes("88ac"),
    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) HexToBytesInitializer {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const HexToBytesInitializer, sig: runar.Sig, pubKey: runar.PubKey, script: runar.ByteString) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.bytesEq(runar.cat(runar.cat(self.p2pkhPrefix, self.pubKeyHash), self.p2pkhSuffix), script));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
