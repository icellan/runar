use runar::prelude::*;

/// OwnerBox -- F-352 second witness for the mutable-state shape {PubKey}.
#[runar::contract]
pub struct OwnerBox {
    pub owner: PubKey,
}

impl OwnerBox {
    pub fn rotate(&mut self, sig: &Sig, new_owner: PubKey) {
        assert!(check_sig(sig, &self.owner));
        self.owner = new_owner;
    }
}
