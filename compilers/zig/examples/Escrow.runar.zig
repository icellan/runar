const runar = @import("runar");

pub const Escrow = struct {
    pub const Contract = runar.SmartContract;

    buyer: runar.PubKey,
    seller: runar.PubKey,
    arbiter: runar.PubKey,

    pub fn init(buyer: runar.PubKey, seller: runar.PubKey, arbiter: runar.PubKey) Escrow {
        return .{ .buyer = buyer, .seller = seller, .arbiter = arbiter };
    }

    pub fn release(self: *const Escrow, buyer_sig: runar.Sig, seller_sig: runar.Sig) void {
        runar.assert(runar.checkSig(buyer_sig, self.buyer));
        runar.assert(runar.checkSig(seller_sig, self.seller));
    }

    pub fn arbitrate(self: *const Escrow, arbiter_sig: runar.Sig, winner_sig: runar.Sig, winner_pub_key: runar.PubKey) void {
        runar.assert(runar.checkSig(arbiter_sig, self.arbiter));
        runar.assert(winner_pub_key == self.buyer or winner_pub_key == self.seller);
        runar.assert(runar.checkSig(winner_sig, winner_pub_key));
    }

    fn verifyParticipant(self: *const Escrow, pub_key: runar.PubKey) bool {
        return pub_key == self.buyer or pub_key == self.seller or pub_key == self.arbiter;
    }
};
