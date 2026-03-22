const runar = @import("runar");

pub const SPHINCSWallet = struct {
    pub const Contract = runar.SmartContract;

    ecdsaPubKeyHash: runar.Addr,
    slhdsaPubKeyHash: runar.ByteString,

    pub fn init(ecdsaPubKeyHash: runar.Addr, slhdsaPubKeyHash: runar.ByteString) SPHINCSWallet {
        return .{
            .ecdsaPubKeyHash = ecdsaPubKeyHash,
            .slhdsaPubKeyHash = slhdsaPubKeyHash,
        };
    }

    pub fn spend(
        self: *const SPHINCSWallet,
        slhdsaSig: runar.ByteString,
        slhdsaPubKey: runar.ByteString,
        sig: runar.Sig,
        pubKey: runar.PubKey,
    ) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.ecdsaPubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
        runar.assert(runar.bytesEq(runar.hash160(slhdsaPubKey), self.slhdsaPubKeyHash));
        runar.assert(runar.verifySLHDSA_SHA2_128s(sig, slhdsaSig, slhdsaPubKey));
    }
};
