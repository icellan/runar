const runar = @import("runar");

pub const P384Wallet = struct {
    pub const Contract = runar.SmartContract;

    ecdsaPubKeyHash: runar.Addr,
    p384PubKeyHash: runar.ByteString,

    pub fn init(ecdsaPubKeyHash: runar.Addr, p384PubKeyHash: runar.ByteString) P384Wallet {
        return .{
            .ecdsaPubKeyHash = ecdsaPubKeyHash,
            .p384PubKeyHash = p384PubKeyHash,
        };
    }

    pub fn spend(
        self: *const P384Wallet,
        p384Sig: runar.ByteString,
        p384PubKey: runar.ByteString,
        sig: runar.Sig,
        pubKey: runar.PubKey,
    ) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.ecdsaPubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
        runar.assert(runar.bytesEq(runar.hash160(p384PubKey), self.p384PubKeyHash));
        runar.assert(runar.verifyECDSA_P384(sig, p384Sig, p384PubKey));
    }
};
