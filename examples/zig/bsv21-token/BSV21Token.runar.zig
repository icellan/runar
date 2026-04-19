const runar = @import("runar");

// BSV21Token — Pay-to-Public-Key-Hash lock for a BSV-21 fungible token.
// BSV-21 uses ID-based tokens (deploy txid + vout) rather than ticker
// names; the locking script is standard P2PKH. See
// examples/ts/bsv21-token/BSV21Token.runar.ts for the full protocol
// description.
pub const BSV21Token = struct {
    pub const Contract = runar.SmartContract;

    pubKeyHash: runar.Addr,

    pub fn init(pubKeyHash: runar.Addr) BSV21Token {
        return .{ .pubKeyHash = pubKeyHash };
    }

    pub fn unlock(self: *const BSV21Token, sig: runar.Sig, pubKey: runar.PubKey) void {
        runar.assert(runar.bytesEq(runar.hash160(pubKey), self.pubKeyHash));
        runar.assert(runar.checkSig(sig, pubKey));
    }
};
