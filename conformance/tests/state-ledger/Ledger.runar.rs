use runar::prelude::*;

/// Ledger -- F-352 second witness for the mutable-state shape
/// {PubKey, bigint, bigint}.
#[runar::contract]
pub struct Ledger {
    pub holder: PubKey,
    pub balance: Bigint,
    pub nonce: Bigint,
}

impl Ledger {
    pub fn spend(&mut self, sig: &Sig, amount: Bigint) {
        assert!(check_sig(sig, &self.holder));
        assert!(amount > 0);
        assert!(amount <= self.balance);
        self.balance = self.balance - amount;
        self.nonce = self.nonce + 1;
    }
}
