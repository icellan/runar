module Escrow {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct Escrow {
        buyer: PubKey,
        seller: PubKey,
        arbiter: PubKey,
    }

    public fun release_by_seller(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.seller), 0);
    }

    public fun release_by_arbiter(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.arbiter), 0);
    }

    public fun refund_to_buyer(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.buyer), 0);
    }

    public fun refund_by_arbiter(contract: &Escrow, sig: Sig) {
        assert!(check_sig(sig, contract.arbiter), 0);
    }
}
