use runar::prelude::*;

#[runar::contract]
struct Escrow {
    #[readonly]
    buyer: PubKey,
    #[readonly]
    seller: PubKey,
    #[readonly]
    arbiter: PubKey,
}

#[runar::methods(Escrow)]
impl Escrow {
    #[public]
    fn release(&self, seller_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(seller_sig, self.seller));
        assert!(check_sig(arbiter_sig, self.arbiter));
    }

    #[public]
    fn refund(&self, buyer_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(buyer_sig, self.buyer));
        assert!(check_sig(arbiter_sig, self.arbiter));
    }
}
