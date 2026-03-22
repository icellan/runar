const runar = @import("runar");

pub const PostQuantumWallet = struct {
    pub const Contract = runar.SmartContract;

    ecdsaPubKeyHash: runar.Addr,
    wotsPubKeyHash: runar.ByteString,

    pub fn init(ecdsaPubKeyHash: runar.Addr, wotsPubKeyHash: runar.ByteString) PostQuantumWallet {
        return .{ .ecdsaPubKeyHash = ecdsaPubKeyHash, .wotsPubKeyHash = wotsPubKeyHash };
    }

    pub fn spend(self: *const PostQuantumWallet, wotsSig: runar.ByteString, wotsPubKey: runar.ByteString, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.hash160(pubKey) == self.ecdsaPubKeyHash);
        runar.assert(runar.checkSig(sig, pubKey));
        runar.assert(runar.hash160(wotsPubKey) == self.wotsPubKeyHash);
        runar.assert(runar.verifyWOTS(sig, wotsSig, wotsPubKey));
    }
};
