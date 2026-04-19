const runar = @import("runar");

pub const P256Wallet = struct {
    pub const Contract = runar.SmartContract;

    ecdsaPubKeyHash: runar.Addr,
    p256PubKeyHash: runar.ByteString,

    pub fn init(ecdsaPubKeyHash: runar.Addr, p256PubKeyHash: runar.ByteString) P256Wallet {
        return .{
            .ecdsaPubKeyHash = ecdsaPubKeyHash,
            .p256PubKeyHash = p256PubKeyHash,
        };
    }

    pub fn spend(
        self: *const P256Wallet,
        p256Sig: runar.ByteString,
        p256PubKey: runar.ByteString,
        sig: runar.Sig,
        pubKey: runar.PubKey,
    ) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.ecdsaPubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
        runar.assert(runar.bytesEq(runar.hash160(p256PubKey), self.p256PubKeyHash));
        runar.assert(runar.verifyECDSA_P256(sig, p256Sig, p256PubKey));
    }
};
