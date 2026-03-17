const runar = @import("runar");

pub const P2PKH = struct {
    pub const Contract = runar.SmartContract;

    pkh: runar.Addr,

    pub fn init(pkh: runar.Addr) P2PKH {
        return .{ .pkh = pkh };
    }

    pub fn unlock(self: *const P2PKH, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.pkh);
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
