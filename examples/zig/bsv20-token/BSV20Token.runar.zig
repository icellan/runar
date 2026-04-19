const runar = @import("runar");

// BSV20Token — Pay-to-Public-Key-Hash lock for a BSV-20 fungible token.
// Token semantics (deploy / mint / transfer) live in the inscription
// envelope interpreted by indexers; the locking script is standard P2PKH.
// See examples/ts/bsv20-token/BSV20Token.runar.ts for the full protocol
// description.
pub const BSV20Token = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) BSV20Token {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const BSV20Token, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
