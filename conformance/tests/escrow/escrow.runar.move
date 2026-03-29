module Escrow {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct Escrow {
        buyer: PubKey,
        seller: PubKey,
        arbiter: PubKey,
    }

    public fun release(contract: &Escrow, seller_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(seller_sig, contract.seller), 0);
        assert!(check_sig(arbiter_sig, contract.arbiter), 0);
    }

    public fun refund(contract: &Escrow, buyer_sig: Sig, arbiter_sig: Sig) {
        assert!(check_sig(buyer_sig, contract.buyer), 0);
        assert!(check_sig(arbiter_sig, contract.arbiter), 0);
    }
}
