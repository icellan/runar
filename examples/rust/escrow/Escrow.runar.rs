use runar::prelude::*;

#[runar::contract]
pub struct Escrow {
    #[readonly]
    pub buyer: PubKey,
    #[readonly]
    pub seller: PubKey,
    #[readonly]
    pub arbiter: PubKey,
}

#[runar::methods(Escrow)]
impl Escrow {
    #[public]
    pub fn release_by_seller(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.seller));
    }

    #[public]
    pub fn release_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }

    #[public]
    pub fn refund_to_buyer(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.buyer));
    }

    #[public]
    pub fn refund_by_arbiter(&self, sig: &Sig) {
        assert!(check_sig(sig, &self.arbiter));
    }
}
