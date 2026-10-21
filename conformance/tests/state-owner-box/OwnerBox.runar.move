// OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
module OwnerBox {
    use runar::types::{PubKey, Sig};
    use runar::crypto::{check_sig};

    resource struct OwnerBox {
        owner: &mut PubKey,
    }

    public fun rotate(contract: &mut OwnerBox, sig: Sig, new_owner: PubKey) {
        assert!(check_sig(sig, contract.owner), 0);
        contract.owner = new_owner;
    }
}
