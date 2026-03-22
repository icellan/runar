const runar = @import("runar");

pub const Escrow = struct {
    pub const Contract = runar.SmartContract;

    buyer: runar.PubKey,
    seller: runar.PubKey,
    arbiter: runar.PubKey,

    pub fn init(buyer: runar.PubKey, seller: runar.PubKey, arbiter: runar.PubKey) Escrow {
        return .{
            .buyer = buyer,
            .seller = seller,
            .arbiter = arbiter,
        };
    }

    pub fn release(self: *const Escrow, sellerSig: runar.Sig, arbiterSig: runar.Sig) void {
        runar.assert(runar.checkSig(sellerSig, self.seller));
        runar.assert(runar.checkSig(arbiterSig, self.arbiter));
    }

    pub fn refund(self: *const Escrow, buyerSig: runar.Sig, arbiterSig: runar.Sig) void {
        runar.assert(runar.checkSig(buyerSig, self.buyer));
        runar.assert(runar.checkSig(arbiterSig, self.arbiter));
    }
};
