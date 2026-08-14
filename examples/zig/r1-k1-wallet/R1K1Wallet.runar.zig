const runar = @import("runar");

/// Hardware-backed P-256 primary spending with independent K1 recovery.
pub const R1K1Wallet = struct {
    pub const Contract = runar.SmartContract;

    r1SaltedPubKeyHash: runar.Addr,
    k1PubKeyHash: runar.Addr,

    pub fn init(r1SaltedPubKeyHash: runar.Addr, k1PubKeyHash: runar.Addr) R1K1Wallet {
        return .{
            .r1SaltedPubKeyHash = r1SaltedPubKeyHash,
            .k1PubKeyHash = k1PubKeyHash,
        };
    }

    pub fn spendR1(
        self: *const R1K1Wallet,
        r1Sig: runar.ByteString,
        r1PubKey: runar.ByteString,
        r1Salt: runar.ByteString,
        txPreimage: runar.SigHashPreimage,
    ) void {
        runar.assert(runar.len(r1Salt) == 32);
        runar.assert(runar.bytesEq(runar.hash160(runar.cat(r1PubKey, r1Salt)), self.r1SaltedPubKeyHash));
        runar.assert(runar.bytesEq(runar.substr(txPreimage, runar.len(txPreimage) - 4, 4), "41000000"));
        runar.assert(runar.checkPreimage(txPreimage));
        runar.assert(runar.verifyECDSA_P256(runar.sha256(txPreimage), r1Sig, r1PubKey));
    }

    pub fn recoverK1(self: *const R1K1Wallet, k1Sig: runar.Sig, k1PubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(k1PubKey), self.k1PubKeyHash));
        runar.assert(runar.checkSig(k1Sig, k1PubKey));
    }
};
