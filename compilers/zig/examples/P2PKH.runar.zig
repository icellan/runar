const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pub_key_hash: runar.Addr,

    pub fn init(pub_key_hash: runar.Addr) P2PKH {
        return .{ .pub_key_hash = pub_key_hash };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pub_key: runar.PubKey) void {
        runar.assert(runar.hash160(pub_key) == self.pub_key_hash);
        runar.assert(runar.checkSig(sig, pub_key));
    }
};
