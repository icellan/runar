const runar = @import("runar");

// OrdinalNFT — Pay-to-Public-Key-Hash lock for a 1sat ordinal NFT. The
// inscription envelope is attached at deployment time via the SDK
// (`withInscription`); the locking script itself is standard P2PKH. See
// examples/ts/ordinal-nft/OrdinalNFT.runar.ts for the full protocol
// description.
pub const OrdinalNFT = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) OrdinalNFT {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const OrdinalNFT, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
